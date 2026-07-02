//go:build windows
// +build windows

package v2ray

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/v2rayA/v2rayA/conf"
	"github.com/v2rayA/v2rayA/db/configure"
	"github.com/v2rayA/v2rayA/pkg/util/log"
	"golang.org/x/sys/windows/registry"
)

const (
	proxifyreBinName        = "ProxiFyre.exe"
	proxifyreConfigFileName = "app-config.json"
	// proxifyreSocksPort is the SOCKS5 port in v2ray dedicated for ProxiFyre traffic.
	// This matches the "transparent" inbound added in setInbound for TransparentProxifyre.
	proxifyreSocksPort = 52345

	// dnsForwarderAddr is the local address the DNS forwarder listens on.
	// All system DNS queries will be redirected here.
	dnsForwarderAddr = "127.0.0.1:53"

	// dnsModuleAddr is the address of the v2raya-core DNS module.
	dnsModuleAddr = "127.2.0.17:52353"
)

// ===================== ProxiFyre Config =====================

// proxifyreConfig represents the app-config.json structure for ProxiFyre.
type proxifyreConfig struct {
	LogLevel  string                 `json:"logLevel"`
	BypassLan bool                   `json:"bypassLan,omitempty"`
	Proxies   []proxifyreProxyConfig `json:"proxies"`
	Excludes  []string               `json:"excludes,omitempty"`
}

type proxifyreProxyConfig struct {
	AppNames            []string `json:"appNames"`
	Socks5ProxyEndpoint string   `json:"socks5ProxyEndpoint"`
	Username            string   `json:"username,omitempty"`
	Password            string   `json:"password,omitempty"`
	SupportedProtocols  []string `json:"supportedProtocols"`
}

// ===================== DNS Forwarder =====================

// dnsForwarder listens on :53 and forwards DNS queries to the v2raya-core
// DNS module.  It is started alongside ProxiFyre to provide DNS anti-pollution
// for the entire system, not just ProxiFyre-captured processes.
type dnsForwarder struct {
	udpConn *net.UDPConn
	tcpLn   net.Listener
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

func newDNSForwarder() *dnsForwarder {
	ctx, cancel := context.WithCancel(context.Background())
	return &dnsForwarder{
		ctx:    ctx,
		cancel: cancel,
	}
}

// start begins listening on UDP/TCP :53 and forwarding to the DNS module.
func (f *dnsForwarder) start() error {
	// UDP
	udpAddr, err := net.ResolveUDPAddr("udp", dnsForwarderAddr)
	if err != nil {
		return fmt.Errorf("dns forwarder: resolve udp addr: %w", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("dns forwarder: listen udp :53: %w", err)
	}
	f.udpConn = udpConn

	// TCP
	tcpLn, err := net.Listen("tcp", dnsForwarderAddr)
	if err != nil {
		f.udpConn.Close()
		return fmt.Errorf("dns forwarder: listen tcp :53: %w", err)
	}
	f.tcpLn = tcpLn

	f.wg.Add(2)
	go f.serveUDP()
	go f.serveTCP()

	log.Info("DNS forwarder listening on %s → %s", dnsForwarderAddr, dnsModuleAddr)
	return nil
}

func (f *dnsForwarder) serveUDP() {
	defer f.wg.Done()
	buf := make([]byte, 1500)
	for {
		select {
		case <-f.ctx.Done():
			return
		default:
		}
		f.udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, clientAddr, err := f.udpConn.ReadFromUDP(buf)
		if err != nil {
			if !isTimeoutOrClosed(err) {
				log.Warn("dns forwarder udp read: %v", err)
			}
			continue
		}
		// Make a copy of the query so the goroutine doesn't share the buffer
		query := make([]byte, n)
		copy(query, buf[:n])
		go f.relayUDP(query, clientAddr)
	}
}

func (f *dnsForwarder) relayUDP(query []byte, clientAddr *net.UDPAddr) {
	upstream, err := net.DialTimeout("udp", dnsModuleAddr, 3*time.Second)
	if err != nil {
		log.Warn("dns forwarder: dial dns module: %v", err)
		return
	}
	defer upstream.Close()
	upstream.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := upstream.Write(query); err != nil {
		log.Warn("dns forwarder: write to dns module: %v", err)
		return
	}
	resp := make([]byte, 1500)
	n, err := upstream.Read(resp)
	if err != nil {
		log.Warn("dns forwarder: read from dns module: %v", err)
		return
	}
	f.udpConn.WriteToUDP(resp[:n], clientAddr)
}

func (f *dnsForwarder) serveTCP() {
	defer f.wg.Done()
	for {
		select {
		case <-f.ctx.Done():
			return
		default:
		}
		f.tcpLn.(*net.TCPListener).SetDeadline(time.Now().Add(1 * time.Second))
		conn, err := f.tcpLn.Accept()
		if err != nil {
			if !isTimeoutOrClosed(err) {
				log.Warn("dns forwarder tcp accept: %v", err)
			}
			continue
		}
		go f.relayTCP(conn)
	}
}

func (f *dnsForwarder) relayTCP(clientConn net.Conn) {
	defer clientConn.Close()
	upstream, err := net.DialTimeout("tcp", dnsModuleAddr, 3*time.Second)
	if err != nil {
		log.Warn("dns forwarder: dial dns module (tcp): %v", err)
		return
	}
	defer upstream.Close()
	upstream.SetDeadline(time.Now().Add(5 * time.Second))
	// Bidirectional copy
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		buf := make([]byte, 1500)
		io.CopyBuffer(upstream, clientConn, buf)
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 1500)
		io.CopyBuffer(clientConn, upstream, buf)
	}()
	wg.Wait()
}

func (f *dnsForwarder) stop() {
	f.cancel()
	if f.udpConn != nil {
		f.udpConn.Close()
	}
	if f.tcpLn != nil {
		f.tcpLn.Close()
	}
	f.wg.Wait()
	log.Info("DNS forwarder stopped")
}

func isTimeoutOrClosed(err error) bool {
	if err == nil {
		return false
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}
	return strings.Contains(err.Error(), "use of closed network connection")
}

// ===================== Windows DNS Adapter Settings =====================

const tcpipInterfacesKey = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`

type adapterDNSSettings struct {
	guid           string
	nameServer     string // saved NameServer value
	dhcpNameServer string // saved DhcpNameServer value
}

var savedAdapterDNS struct {
	mu       sync.Mutex
	adapters []adapterDNSSettings
	saved    bool
}

// enumerateAdapters returns GUIDs of all network adapters.
func enumerateAdapters() ([]string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, tcpipInterfacesKey, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, fmt.Errorf("open interfaces key: %w", err)
	}
	defer k.Close()
	return k.ReadSubKeyNames(0)
}

// readAdapterDNSSettings reads NameServer and DhcpNameServer from an adapter's registry key.
func readAdapterDNSSettings(guid string) (nameServer, dhcpNameServer string, err error) {
	keyPath := tcpipInterfacesKey + `\` + guid
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.READ)
	if err != nil {
		return "", "", fmt.Errorf("open adapter key %s: %w", guid, err)
	}
	defer k.Close()
	ns, _, err := k.GetStringValue("NameServer")
	if err == nil {
		nameServer = ns
	}
	dhcp, _, err := k.GetStringValue("DhcpNameServer")
	if err == nil {
		dhcpNameServer = dhcp
	}
	return
}

// setAdapterDNSServer sets an adapter's DNS server via netsh.
// This is more reliable than writing to the registry directly because
// netsh triggers the Windows network stack to re-read the settings.
func setAdapterDNSServer(guid string) error {
	// Get the adapter name from the GUID. The best way is via netsh.
	// First try to get the name, then set DNS.
	out, err := exec.Command("netsh", "interface", "ip", "show", "interfaces").CombinedOutput()
	if err != nil {
		// Fallback: try setting by GUID via registry write
		return setAdapterDNSServerRegistry(guid)
	}
	// Parse netsh output to find adapter name for this GUID
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, guid) || strings.Contains(line, strings.ToUpper(guid)) {
			// Found the adapter line. Format varies by Windows version.
			// "  17   Ethernet   Ethernet0   connected" → name is at index 3+
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				adapterName := strings.Join(fields[3:], " ")
				cmd := exec.Command("netsh", "interface", "ip", "set", "dns",
					adapterName, "static", "127.0.0.1")
				if output, err := cmd.CombinedOutput(); err != nil {
					log.Warn("dns hijack: netsh set dns failed for adapter %q (guid=%s): %v\n%s",
						adapterName, guid, err, string(output))
					return setAdapterDNSServerRegistry(guid)
				}
				return nil
			}
		}
	}
	// Fallback
	return setAdapterDNSServerRegistry(guid)
}

// setAdapterDNSServerRegistry sets an adapter's DNS server by writing to the registry.
func setAdapterDNSServerRegistry(guid string) error {
	keyPath := tcpipInterfacesKey + `\` + guid
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open adapter key for write %s: %w", guid, err)
	}
	defer k.Close()
	return k.SetStringValue("NameServer", "127.0.0.1")
}

// restoreAdapterDNSServer restores an adapter's original DNS server settings.
func restoreAdapterDNSServer(guid, nameServer, dhcpNameServer string) {
	keyPath := tcpipInterfacesKey + `\` + guid
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.SET_VALUE)
	if err != nil {
		log.Warn("dns hijack restore: open adapter key %s: %v", guid, err)
		return
	}
	defer k.Close()
	if nameServer != "" {
		if err := k.SetStringValue("NameServer", nameServer); err != nil {
			log.Warn("dns hijack restore: set NameServer for %s: %v", guid, err)
		}
	} else {
		// If no static NameServer was configured, delete the value entirely
		// so DHCP takes over.
		if err := k.DeleteValue("NameServer"); err != nil && !os.IsNotExist(err) {
			log.Warn("dns hijack restore: delete NameServer for %s: %v", guid, err)
		}
		// If there was a DhcpNameServer, the system will use it automatically.
	}
}

// saveAdaptersDNSSettings saves current DNS settings for all adapters.
func saveAdaptersDNSSettings() {
	savedAdapterDNS.mu.Lock()
	defer savedAdapterDNS.mu.Unlock()
	if savedAdapterDNS.saved {
		return
	}
	guids, err := enumerateAdapters()
	if err != nil {
		log.Warn("dns hijack: enumerate adapters: %v", err)
		return
	}
	for _, guid := range guids {
		ns, dhcp, err := readAdapterDNSSettings(guid)
		if err != nil {
			log.Warn("dns hijack: read adapter %s: %v", guid, err)
			continue
		}
		if ns == "" && dhcp == "" {
			continue // no DNS configured on this adapter
		}
		savedAdapterDNS.adapters = append(savedAdapterDNS.adapters, adapterDNSSettings{
			guid:           guid,
			nameServer:     ns,
			dhcpNameServer: dhcp,
		})
	}
	savedAdapterDNS.saved = true
	log.Trace("dns hijack: saved DNS settings for %d adapters", len(savedAdapterDNS.adapters))
}

// setAllAdaptersDNSToLocal sets the DNS server of all adapters to 127.0.0.1.
func setAllAdaptersDNSToLocal() {
	guids, err := enumerateAdapters()
	if err != nil {
		log.Warn("dns hijack: enumerate adapters for setting: %v", err)
		return
	}
	for _, guid := range guids {
		if err := setAdapterDNSServer(guid); err != nil {
			log.Warn("dns hijack: set adapter %s: %v", guid, err)
		}
	}
	log.Info("DNS hijack: set all adapters DNS → 127.0.0.1")
}

// restoreAdaptersDNSSettings restores saved DNS settings for all adapters.
func restoreAdaptersDNSSettings() {
	savedAdapterDNS.mu.Lock()
	adapters := savedAdapterDNS.adapters
	savedAdapterDNS.adapters = nil
	savedAdapterDNS.saved = false
	savedAdapterDNS.mu.Unlock()

	for _, a := range adapters {
		restoreAdapterDNSServer(a.guid, a.nameServer, a.dhcpNameServer)
	}
	if len(adapters) > 0 {
		log.Info("DNS hijack: restored DNS settings for %d adapters", len(adapters))
		// Flush DNS cache
		exec.Command("ipconfig", "/flushdns").Run()
	}
}

// ===================== ProxiFyre Process State =====================

// proxifyreState tracks the running ProxiFyre process.
var proxifyreState struct {
	cancel   context.CancelFunc
	done     chan struct{} // closed by the monitor goroutine when cmd.Wait() returns
	mu       sync.Mutex
	stopping int32 // atomic; 1 while stopProxifyre is in progress

	// DNS forwarder instance (only on Windows)
	dnsFwd *dnsForwarder
}

// ===================== Binary Path Resolution =====================

// GetProxifyreBinPath returns the path to the ProxiFyre binary.
// It first checks the --proxifyre-bin / V2RAYA_PROXIFYRE_BIN configuration,
// then searches PATH and the current working directory.
func GetProxifyreBinPath() (string, error) {
	if binPath := conf.GetEnvironmentConfig().ProxifyreBin; binPath != "" {
		return binPath, nil
	}
	return getProxifyreBinPathAuto()
}

func getProxifyreBinPathAuto() (string, error) {
	target := proxifyreBinName
	if runtime.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(target), ".exe") {
		target += ".exe"
	}
	// Search in the same directory as the executable
	if exe, err := os.Executable(); err == nil {
		path := filepath.Join(filepath.Dir(exe), target)
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	// Search PATH
	if path, err := exec.LookPath(target); err == nil {
		return path, nil
	}
	return "", fmt.Errorf("ProxiFyre binary not found: please place ProxiFyre.exe next to v2rayA.exe or use --proxifyre-bin to specify its path")
}

// ===================== Config Generation =====================

// generateProxifyreConfig generates the app-config.json file for ProxiFyre.
func generateProxifyreConfig(tmpl *Template) (string, error) {
	setting := configure.GetSettingNotNil()

	// Map v2rayA log level to ProxiFyre log level
	proxifyreLogLevel := mapLogLevel(setting.LogLevel)

	// Build the proxy config pointing to v2rayA's SOCKS5 port
	proxyEndpoint := fmt.Sprintf("127.0.0.1:%d", proxifyreSocksPort)

	proxy := proxifyreProxyConfig{
		AppNames:            []string{""}, // empty string matches all processes
		Socks5ProxyEndpoint: proxyEndpoint,
		SupportedProtocols:  []string{"TCP", "UDP"},
	}

	cfg := proxifyreConfig{
		LogLevel:  proxifyreLogLevel,
		BypassLan: setting.TproxyExcludedInterfaces != "", // reuse existing field signal
		Proxies:   []proxifyreProxyConfig{proxy},
	}

	// Build the exclusion list.
	// Mandatory excludes (absolute paths): these processes must never be proxied
	// to avoid routing loops (v2raya.exe, v2raya_core.exe, ProxiFyre.exe).
	mandatoryExcludes := buildMandatoryExcludes()

	// User-provided custom excludes (comma-separated list of names or paths).
	userExcludes := parseUserExcludes(setting.ProxifyreExcludeProcesses)

	// Combine: mandatory first, then user-defined.
	cfg.Excludes = append(mandatoryExcludes, userExcludes...)

	// Generate config file path next to the ProxiFyre binary
	binPath, err := GetProxifyreBinPath()
	if err != nil {
		return "", fmt.Errorf("generateProxifyreConfig: %w", err)
	}
	configPath := filepath.Join(filepath.Dir(binPath), proxifyreConfigFileName)

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", fmt.Errorf("generateProxifyreConfig: failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return "", fmt.Errorf("generateProxifyreConfig: failed to write config: %w", err)
	}

	log.Trace("Generated ProxiFyre config at %s", configPath)
	return configPath, nil
}

// buildMandatoryExcludes returns a list of absolute process paths that must
// never be proxied to avoid routing loops.
//
// The following processes are always excluded:
//   - The v2rayA host process itself (v2raya.exe)
//   - The v2ray/xray core child process (v2raya_core.exe)
//   - ProxiFyre.exe itself
func buildMandatoryExcludes() []string {
	excludes := []string{}

	// Exclude the current executable (v2raya.exe) by absolute path
	if exe, err := os.Executable(); err == nil {
		absExe, err := filepath.Abs(exe)
		if err == nil {
			excludes = append(excludes, absExe)
		}
	}

	// Exclude v2raya_core by searching for it next to the current binary
	if exe, err := os.Executable(); err == nil {
		corePath := filepath.Join(filepath.Dir(exe), "v2raya_core")
		if _, err := os.Stat(corePath); err == nil {
			absCore, _ := filepath.Abs(corePath)
			excludes = append(excludes, absCore)
		}
		// Also try with .exe extension
		corePathExe := corePath + ".exe"
		if _, err := os.Stat(corePathExe); err == nil {
			absCoreExe, _ := filepath.Abs(corePathExe)
			excludes = append(excludes, absCoreExe)
		}
	}

	// Exclude ProxiFyre.exe itself
	if binPath, err := GetProxifyreBinPath(); err == nil {
		absBin, err := filepath.Abs(binPath)
		if err == nil {
			excludes = append(excludes, absBin)
		}
	}

	return excludes
}

// parseUserExcludes parses a comma-separated string of process names or paths
// into a slice.  Empty entries are dropped.
func parseUserExcludes(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// mapLogLevel converts v2rayA log level to ProxiFyre log level.
func mapLogLevel(level string) string {
	switch strings.ToLower(level) {
	case "error":
		return "Error"
	case "warning", "warn":
		return "Warning"
	case "info":
		return "Info"
	case "debug":
		return "Debug"
	case "trace", "all":
		return "All"
	default:
		return "Info"
	}
}

// ===================== Lifecycle =====================

// startProxifyre starts the ProxiFyre process and sets up DNS hijacking.
func startProxifyre(tmpl *Template) error {
	binPath, err := GetProxifyreBinPath()
	if err != nil {
		return err
	}

	if _, err := generateProxifyreConfig(tmpl); err != nil {
		return err
	}

	// Verify that app-config.json was written to the correct location
	expectedConfigPath := filepath.Join(filepath.Dir(binPath), proxifyreConfigFileName)
	if _, err := os.Stat(expectedConfigPath); err != nil {
		return fmt.Errorf("startProxifyre: config file not found at %s: %w", expectedConfigPath, err)
	}

	proxifyreState.mu.Lock()
	defer proxifyreState.mu.Unlock()

	// If already running, stop first
	if proxifyreState.cancel != nil {
		log.Warn("startProxifyre: ProxiFyre is already running, stopping first")
		proxifyreState.mu.Unlock()
		stopProxifyre()
		proxifyreState.mu.Lock()
	}

	// Step 1: Set up DNS hijacking before starting the proxy.
	// Save current adapter DNS settings and redirect all DNS to local forwarder.
	saveAdaptersDNSSettings()
	setAllAdaptersDNSToLocal()

	// Step 2: Start the DNS forwarder (listens on :53, forwards to DNS module :52353).
	dnsFwd := newDNSForwarder()
	if err := dnsFwd.start(); err != nil {
		restoreAdaptersDNSSettings()
		return fmt.Errorf("startProxifyre: dns forwarder: %w", err)
	}

	// Step 3: Start ProxiFyre process.
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, binPath)
	cmd.Dir = filepath.Dir(binPath)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		dnsFwd.stop()
		restoreAdaptersDNSSettings()
		return fmt.Errorf("startProxifyre: failed to create stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		dnsFwd.stop()
		restoreAdaptersDNSSettings()
		return fmt.Errorf("startProxifyre: failed to create stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		cancel()
		dnsFwd.stop()
		restoreAdaptersDNSSettings()
		return fmt.Errorf("startProxifyre: failed to start ProxiFyre: %w", err)
	}

	doneCh := make(chan struct{})
	proxifyreState.cancel = cancel
	proxifyreState.done = doneCh
	proxifyreState.dnsFwd = dnsFwd
	atomic.StoreInt32(&proxifyreState.stopping, 0)

	// Log ProxiFyre output in background
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				log.Info("[ProxiFyre] %s", strings.TrimRight(string(buf[:n]), "\r\n"))
			}
			if err != nil {
				break
			}
		}
	}()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := stderr.Read(buf)
			if n > 0 {
				log.Warn("[ProxiFyre] %s", strings.TrimRight(string(buf[:n]), "\r\n"))
			}
			if err != nil {
				break
			}
		}
	}()

	// Monitor process exit
	go func() {
		err := cmd.Wait()
		close(doneCh)

		select {
		case <-ctx.Done():
			return // intentional stop
		default:
		}

		if atomic.LoadInt32(&proxifyreState.stopping) != 0 {
			return
		}

		// Unexpected exit
		log.Warn("ProxiFyre process exited unexpectedly: %v", err)
		log.Warn("Please ensure WinpkFilter (Windows Packet Filter) is installed and ProxiFyre.exe is allowed through Windows Firewall.")
		log.Warn("To allow ProxiFyre through firewall, run as admin:")
		log.Warn("  netsh advfirewall firewall add rule name=\"ProxiFyre\" dir=in action=allow program=\"%s\" enable=yes", binPath)
		log.Warn("  netsh advfirewall firewall add rule name=\"ProxiFyre\" dir=out action=allow program=\"%s\" enable=yes", binPath)
	}()

	// Give it a moment to start, then check if it's still running
	time.Sleep(500 * time.Millisecond)
	if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
		dnsFwd.stop()
		restoreAdaptersDNSSettings()
		return fmt.Errorf("startProxifyre: ProxiFyre exited immediately. Check that WinpkFilter is installed and run v2rayA as Administrator")
	}

	log.Info("ProxiFyre started successfully (PID: %d)", cmd.Process.Pid)
	log.Warn("=== IMPORTANT: Firewall Notice ===")
	log.Warn("ProxiFyre needs to accept and initiate network connections.")
	log.Warn("If transparent proxy does not work, add firewall rules for ProxiFyre.exe:")
	log.Warn("  netsh advfirewall firewall add rule name=\"ProxiFyre\" dir=in action=allow program=\"%s\" enable=yes", binPath)
	log.Warn("  netsh advfirewall firewall add rule name=\"ProxiFyre\" dir=out action=allow program=\"%s\" enable=yes", binPath)
	log.Warn("Or use Windows Defender Firewall with Advanced Security GUI.")

	return nil
}

// stopProxifyre stops the running ProxiFyre process and restores DNS settings.
func stopProxifyre() {
	proxifyreState.mu.Lock()
	cancel := proxifyreState.cancel
	doneCh := proxifyreState.done
	dnsFwd := proxifyreState.dnsFwd
	proxifyreState.mu.Unlock()

	if cancel == nil {
		return
	}

	atomic.StoreInt32(&proxifyreState.stopping, 1)

	// Stop DNS forwarder first so it stops accepting new queries
	if dnsFwd != nil {
		dnsFwd.stop()
	}

	// Restore original DNS server settings on all adapters
	restoreAdaptersDNSSettings()

	// Then stop ProxiFyre process
	cancel()

	// Wait for the process to exit with a timeout
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()

	select {
	case <-doneCh:
		log.Info("ProxiFyre process stopped gracefully")
	case <-timer.C:
		log.Warn("ProxiFyre process did not exit within 5s, forcing termination")
	}

	proxifyreState.mu.Lock()
	proxifyreState.cancel = nil
	proxifyreState.done = nil
	proxifyreState.dnsFwd = nil
	proxifyreState.mu.Unlock()

	atomic.StoreInt32(&proxifyreState.stopping, 0)
}

// IsProxifyreEnabled reports whether ProxiFyre support is available.
// On Windows, this is always true (runtime detection of the binary).
// The actual availability depends on the presence of ProxiFyre.exe at runtime.
func IsProxifyreEnabled() bool {
	_, err := GetProxifyreBinPath()
	return err == nil
}
