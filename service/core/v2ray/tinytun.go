package v2ray

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	jsoniter "github.com/json-iterator/go"
	"github.com/v2rayA/v2rayA/conf"
	"github.com/v2rayA/v2rayA/pkg/util/log"
)

// tinytunTunConf represents the TUN interface settings in TinyTun config.
type tinytunTunConf struct {
	Name      string `json:"name"`
	IP        string `json:"ip"`
	Netmask   string `json:"netmask"`
	Ipv6Mode  string `json:"ipv6_mode,omitempty"`
	AutoRoute bool   `json:"auto_route"`
	MTU       int    `json:"mtu,omitempty"`
}

// tinytunSocks5Conf represents the SOCKS5 proxy settings in TinyTun config.
type tinytunSocks5Conf struct {
	Address      string `json:"address"`
	DnsOverSocks bool   `json:"dns_over_socks5"`
}

// tinytunDnsServerConf represents a single DNS server entry in TinyTun config.
type tinytunDnsServerConf struct {
	Address string `json:"address"`
	Route   string `json:"route"`
}

// tinytunDnsConf represents the DNS settings in TinyTun config.
type tinytunDnsConf struct {
	Servers []tinytunDnsServerConf `json:"servers"`
}

// tinytunFilteringConf represents the filtering settings in TinyTun config.
type tinytunFilteringConf struct {
	SkipIPs      []string `json:"skip_ips,omitempty"`
	SkipNetworks []string `json:"skip_networks,omitempty"`
}

// tinytunConfig is the top-level TinyTun JSON configuration.
type tinytunConfig struct {
	Tun       tinytunTunConf       `json:"tun"`
	Socks5    tinytunSocks5Conf    `json:"socks5"`
	DNS       tinytunDnsConf       `json:"dns"`
	Filtering tinytunFilteringConf `json:"filtering"`
}

const (
	tinytunBinName        = "tinytun"
	tinytunConfigFileName = "tinytun.json"
	// tinytunSocksPort is the SOCKS5 port in v2ray dedicated for TinyTun traffic.
	// This matches the "transparent" inbound added in setInbound for TransparentTun.
	tinytunSocksPort = 52345
)

// tinyTunState tracks the running TinyTun process.
var tinyTunState struct {
	cancel context.CancelFunc
	mu     sync.Mutex
}

// GetTinyTunBinPath returns the path to the TinyTun binary.
// It first checks the --tinytun-bin / V2RAYA_TINYTUN_BIN configuration,
// then searches PATH and the current working directory.
func GetTinyTunBinPath() (string, error) {
	if binPath := conf.GetEnvironmentConfig().TinyTunBin; binPath != "" {
		return binPath, nil
	}
	return getTinyTunBinPathAuto()
}

func getTinyTunBinPathAuto() (string, error) {
	target := tinytunBinName
	if runtime.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(target), ".exe") {
		target += ".exe"
	}
	// Search in PATH
	if path, err := exec.LookPath(target); err == nil {
		return path, nil
	}
	// Search in current working directory
	pwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("tinytun binary not found: please install tinytun or use --tinytun-bin")
	}
	path := filepath.Join(pwd, target)
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}
	return "", fmt.Errorf("tinytun binary not found: please install tinytun or use --tinytun-bin to specify its path")
}

// resolveHostToIPs resolves a hostname to a list of IP strings.
// If the input is already an IP address it is returned as-is.
func resolveHostToIPs(hostname string) ([]string, error) {
	if ip := net.ParseIP(hostname); ip != nil {
		return []string{ip.String()}, nil
	}
	addrs, err := net.LookupHost(hostname)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve %v: %w", hostname, err)
	}
	return addrs, nil
}

// collectNodeIPs returns the deduplicated list of IP addresses for all proxy
// nodes referenced by tmpl. Domain-based node addresses are resolved to IPs.
func collectNodeIPs(tmpl *Template) []string {
	seen := make(map[string]struct{})
	var result []string
	for _, info := range tmpl.serverInfoMap {
		hostname := info.Info.GetHostname()
		ips, err := resolveHostToIPs(hostname)
		if err != nil {
			log.Warn("tinytun: failed to resolve node hostname %v: %v", hostname, err)
			continue
		}
		for _, ip := range ips {
			if _, ok := seen[ip]; !ok {
				seen[ip] = struct{}{}
				result = append(result, ip)
			}
		}
	}
	return result
}

// generateTinyTunConfig generates a TinyTun JSON config file and returns its path.
func generateTinyTunConfig(tmpl *Template) (string, error) {
	nodeIPs := collectNodeIPs(tmpl)

	cfg := tinytunConfig{
		Tun: tinytunTunConf{
			Name:      "tun0",
			IP:        "198.18.0.1",
			Netmask:   "255.255.255.255",
			AutoRoute: true,
			MTU:       1500,
		},
		Socks5: tinytunSocks5Conf{
			Address:      fmt.Sprintf("127.0.0.1:%d", tinytunSocksPort),
			DnsOverSocks: true,
		},
		DNS: tinytunDnsConf{
			Servers: []tinytunDnsServerConf{
				{Address: "8.8.8.8:53", Route: "proxy"},
			},
		},
		Filtering: tinytunFilteringConf{
			SkipIPs: nodeIPs,
			SkipNetworks: []string{
				"192.168.0.0/16",
				"172.16.0.0/12",
				"10.0.0.0/8",
				"127.0.0.0/8",
				"169.254.0.0/16",
			},
		},
	}

	data, err := jsoniter.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal tinytun config: %w", err)
	}

	configPath := filepath.Join(conf.GetEnvironmentConfig().Config, tinytunConfigFileName)
	if err = os.WriteFile(configPath, data, 0600); err != nil {
		return "", fmt.Errorf("failed to write tinytun config to %v: %w", configPath, err)
	}
	return configPath, nil
}

// startTinyTun generates the TinyTun config and starts the TinyTun process.
func startTinyTun(tmpl *Template) error {
	binPath, err := GetTinyTunBinPath()
	if err != nil {
		return err
	}

	configPath, err := generateTinyTunConfig(tmpl)
	if err != nil {
		return err
	}

	log.Info("Starting TinyTun from %v with config %v", binPath, configPath)

	ctx, cancel := context.WithCancel(context.Background())

	_, err = RunWithLog(ctx, binPath, []string{binPath, "run", "--config", configPath}, "", os.Environ())
	if err != nil {
		cancel()
		return fmt.Errorf("failed to start tinytun: %w", err)
	}

	tinyTunState.mu.Lock()
	if tinyTunState.cancel != nil {
		tinyTunState.cancel()
	}
	tinyTunState.cancel = cancel
	tinyTunState.mu.Unlock()

	return nil
}

// stopTinyTun stops the running TinyTun process if one is active.
func stopTinyTun() {
	tinyTunState.mu.Lock()
	cancel := tinyTunState.cancel
	tinyTunState.cancel = nil
	tinyTunState.mu.Unlock()

	if cancel != nil {
		log.Info("Stopping TinyTun")
		cancel()
	}
}
