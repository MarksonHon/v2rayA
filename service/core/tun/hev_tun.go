package tun

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sync"
	"time"

	"github.com/v2rayA/v2rayA/conf"
	"github.com/v2rayA/v2rayA/pkg/util/log"
	"gopkg.in/yaml.v3"
)

// BinaryProbe reports the presence of the v2raya-tun helper.
type BinaryProbe struct {
	Available bool
	Path      string
	Err       error
}

// DetectBinary locates the v2raya-tun binary in PATH.
func DetectBinary() BinaryProbe {
	path, err := exec.LookPath("v2raya-tun")
	if err != nil {
		return BinaryProbe{Available: false, Err: err}
	}
	return BinaryProbe{Available: true, Path: path}
}

type hevTun struct {
	mu               sync.Mutex
	cmd              *exec.Cmd
	cancel           context.CancelFunc
	waitCh           chan struct{}
	whitelistDomains []string
	whitelistAddrs   []netip.Addr
	useFakeIP        bool
	useIPv6          bool
	strictRoute      bool
	autoRoute        bool
	postScript       string
	lastConfigPath   string
	lastBinaryPath   string
}

// NewHevTun creates a Hev-based TUN runner.
func NewHevTun() Tun {
	return &hevTun{
		autoRoute: true,
		useFakeIP: true,
	}
}

func (t *hevTun) Start(stack Stack) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	_ = t.closeLocked()

	probe := DetectBinary()
	t.lastBinaryPath = probe.Path
	if !probe.Available {
		log.Warn("[TUN] v2raya-tun not found in PATH: %v", probe.Err)
		return errors.New("v2raya-tun not found")
	}
	log.Info("[TUN] using v2raya-tun binary at %s (stack=%s)", probe.Path, stack)

	cfg := t.buildConfig()
	configBytes, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	configPath := tunConfigPath()
	if err := os.WriteFile(configPath, configBytes, 0o600); err != nil {
		return err
	}
	t.lastConfigPath = configPath

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, probe.Path, configPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		cancel()
		return err
	}
	t.cmd = cmd
	t.cancel = cancel
	t.waitCh = make(chan struct{})

	go func() {
		_ = cmd.Wait()
		close(t.waitCh)
	}()

	// Apply host routing rules per-OS when auto-routing is enabled
	if t.autoRoute {
		excludes := t.buildExcludePrefixes()
		if err := applyRoutes(RouteOptions{TunName: cfg.Tunnel.Name, Exclude: excludes}); err != nil {
			log.Warn("[TUN] apply routes failed: %v", err)
		}
	} else if t.postScript != "" {
		go runPostScript(t.postScript)
	}

	return nil
}

func (t *hevTun) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closeLocked()
}

func (t *hevTun) closeLocked() error {
	if t.cancel != nil {
		t.cancel()
	}
	if t.waitCh != nil {
		select {
		case <-t.waitCh:
		case <-time.After(5 * time.Second):
			if t.cmd != nil {
				_ = t.cmd.Process.Kill()
			}
		}
	}
	_ = cleanupRoutes()
	t.cmd = nil
	t.cancel = nil
	t.waitCh = nil
	return nil
}

func (t *hevTun) AddDomainWhitelist(domain string) {
	if domain == "" {
		return
	}
	t.whitelistDomains = append(t.whitelistDomains, domain)
}

func (t *hevTun) AddIPWhitelist(addr netip.Addr) {
	if !addr.IsValid() {
		return
	}
	t.whitelistAddrs = append(t.whitelistAddrs, addr)
}

func (t *hevTun) SetFakeIP(enabled bool) { t.useFakeIP = enabled }

func (t *hevTun) SetIPv6(enabled bool) { t.useIPv6 = enabled }

func (t *hevTun) SetStrictRoute(enabled bool) { t.strictRoute = enabled }

func (t *hevTun) SetAutoRoute(enabled bool) { t.autoRoute = enabled }

func (t *hevTun) SetPostScript(script string) { t.postScript = script }

// buildExcludePrefixes converts whitelisted domains/IPs into prefixes used by route managers.
func (t *hevTun) buildExcludePrefixes() []netip.Prefix {
	excludes := make([]netip.Prefix, 0, len(t.whitelistAddrs)+len(t.whitelistDomains))
	for _, addr := range t.whitelistAddrs {
		excludes = append(excludes, netip.PrefixFrom(addr, addr.BitLen()))
	}
	if len(t.whitelistDomains) > 0 {
		excludes = append(excludes, ResolveDnsServersToExcludes(t.whitelistDomains)...)
	}
	return excludes
}

// hevConfig mirrors the YAML expected by hev-socks5-tunnel.
type hevConfig struct {
	Tunnel tunnelConfig  `yaml:"tunnel"`
	Socks5 socks5Config  `yaml:"socks5"`
	MapDNS *mapdnsConfig `yaml:"mapdns,omitempty"`
	Misc   miscConfig    `yaml:"misc"`
}

type tunnelConfig struct {
	Name       string `yaml:"name"`
	MTU        int    `yaml:"mtu"`
	MultiQueue bool   `yaml:"multi-queue"`
	IPv4       string `yaml:"ipv4"`
	IPv6       string `yaml:"ipv6,omitempty"`
}

type socks5Config struct {
	Port     int    `yaml:"port"`
	Address  string `yaml:"address"`
	UDP      string `yaml:"udp"`
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`
	Mark     int    `yaml:"mark"`
}

type mapdnsConfig struct {
	Address   string `yaml:"address"`
	Port      int    `yaml:"port"`
	Network   string `yaml:"network"`
	Netmask   string `yaml:"netmask"`
	CacheSize int    `yaml:"cache-size,omitempty"`
}

type miscConfig struct {
	LogLevel string `yaml:"log-level"`
	PidFile  string `yaml:"pid-file,omitempty"`
	LogFile  string `yaml:"log-file,omitempty"`
}

func tunConfigPath() string {
	return path.Join(conf.GetEnvironmentConfig().Config, "v2raya-tun.yaml")
}

func tunLogPath() string {
	mainLog := conf.GetEnvironmentConfig().LogFile
	if mainLog != "" {
		if dir := filepath.Dir(mainLog); dir != "" && dir != "." {
			return filepath.Join(dir, "v2raya-tun.log")
		}
	}
	return filepath.Join(conf.GetEnvironmentConfig().Config, "v2raya-tun.log")
}

func (t *hevTun) buildConfig() hevConfig {
	cfg := hevConfig{
		Tunnel: tunnelConfig{
			Name:       defaultTunName,
			MTU:        defaultMTU,
			MultiQueue: false,
			IPv4:       defaultIPv4,
		},
		Socks5: socks5Config{
			Port:    52345,
			Address: "127.0.0.1",
			UDP:     "udp",
			Mark:    defaultMark,
		},
		Misc: miscConfig{
			LogLevel: "warn", // reduce helper noise (socks5 client udp construct spam)
			LogFile:  tunLogPath(),
		},
	}
	if t.useIPv6 {
		cfg.Tunnel.IPv6 = defaultIPv6
	}
	if t.useFakeIP {
		cfg.MapDNS = &mapdnsConfig{
			Address: defaultMapDNS,
			Port:    53,
			Network: defaultMapDNSNetwork,
			Netmask: defaultMapDNSNetmask,
		}
	}
	return cfg
}
