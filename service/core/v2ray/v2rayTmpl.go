package v2ray

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-leo/slicex"

	jsoniter "github.com/json-iterator/go"
	"github.com/mohae/deepcopy"
	"github.com/v2rayA/RoutingA"
	"github.com/v2rayA/v2rayA/common"
	"github.com/v2rayA/v2rayA/common/netTools/netstat"
	"github.com/v2rayA/v2rayA/common/netTools/ports"
	"github.com/v2rayA/v2rayA/conf"
	"github.com/v2rayA/v2rayA/core/coreObj"
	"github.com/v2rayA/v2rayA/core/iptables"
	"github.com/v2rayA/v2rayA/core/serverObj"
	"github.com/v2rayA/v2rayA/core/tun"
	"github.com/v2rayA/v2rayA/core/v2ray/asset"
	"github.com/v2rayA/v2rayA/core/v2ray/where"
	"github.com/v2rayA/v2rayA/db/configure"
	"github.com/v2rayA/v2rayA/pkg/plugin"
	"github.com/v2rayA/v2rayA/pkg/util/log"
)

type Template struct {
	Log       *coreObj.Log             `json:"log,omitempty"`
	Inbounds  []coreObj.Inbound        `json:"inbounds"`
	Outbounds []coreObj.OutboundObject `json:"outbounds"`
	Routing   struct {
		DomainStrategy string                `json:"domainStrategy"`
		DomainMatcher  string                `json:"domainMatcher,omitempty"`
		Rules          []coreObj.RoutingRule `json:"rules"`
		Balancers      []coreObj.Balancer    `json:"balancers,omitempty"`
	} `json:"routing"`
	DNS              *coreObj.DNS              `json:"dns,omitempty"`
	FakeDns          *coreObj.FakeDns          `json:"fakedns,omitempty"`
	MultiObservatory *coreObj.MultiObservatory `json:"multiObservatory,omitempty"`
	Observatory      *coreObj.ObservatoryItem  `json:"observatory,omitempty"`
	API              *coreObj.APIObject        `json:"api,omitempty"`

	Variant               where.Variant          `json:"-"`
	CoreVersion           string                 `json:"-"`
	Plugins               []plugin.Server        `json:"-"`
	OutboundTags          []string               `json:"-"`
	ApiCloses             []func()               `json:"-"`
	ApiPort               int                    `json:"-"`
	Setting               *configure.Setting     `json:"-"`
	PluginManagerInfoList []PluginManagerInfo    `json:"-"`
	serverInfoMap         map[string]*serverInfo `json:"-"` // outbound tag -> server info
}

type PluginManagerInfo struct {
	Link string
	Port int
}

func (t *Template) Close() error {
	var err error
	for _, p := range t.Plugins {
		if e := p.Close(); err == nil && e != nil {
			err = e
		}
	}
	for _, f := range t.ApiCloses {
		f()
	}
	return err
}

func (t *Template) ServePlugins() error {
	var wg sync.WaitGroup
	var err error
	for _, p := range t.Plugins {
		wg.Add(1)
		nodeName := p.NodeName()
		if nodeName == "" {
			nodeName = "unknown"
		}
		log.Trace("[v2ray] starting plugin on %s (node: %s)", p.ListenAddr(), nodeName)
		go func(p plugin.Server) {
			if e := p.ListenAndServe(); e != nil {
				log.Warn("[v2ray] plugin on %s (node: %s) exited with error: %v", p.ListenAddr(), p.NodeName(), e)
				err = e
			} else {
				log.Trace("[v2ray] plugin on %s (node: %s) stopped", p.ListenAddr(), p.NodeName())
			}
			wg.Done()
		}(p)
	}
	log.Trace("[v2ray] all plugins are starting...")
	return err
}

type Addr struct {
	host string
	port string
	udp  bool
}

// ExtractDirectDnsServerHosts returns the hostnames/IPs of DNS servers whose outbound is NOT "proxy".
// Only these servers need to be excluded from TUN routing (direct traffic must bypass TUN;
// proxy-bound DNS servers should remain inside TUN so they are proxied correctly).
// The nodeResolveDns bootstrap server is always direct and is always included.
func ExtractDirectDnsServerHosts(setting *configure.Setting) []string {
	if setting == nil {
		return nil
	}
	seen := make(map[string]bool)
	var hosts []string
	add := func(addr string) {
		h := parseDnsAddr(addr).host
		if h == "" || h == "localhost" || h == "fakedns" || seen[h] {
			return
		}
		seen[h] = true
		hosts = append(hosts, h)
	}

	for _, entry := range setting.DnsServers {
		if entry.Address == "" {
			continue
		}
		// "proxy" DNS servers should NOT be excluded — their traffic must go through TUN/proxy.
		if entry.Outbound == "proxy" {
			continue
		}
		add(entry.Address)
	}

	// nodeResolveDns is always routed direct; include it unconditionally.
	nrDns := setting.NodeResolveDns
	if nrDns == "" {
		nrDns = "https://223.5.5.5/dns-query"
	}
	add(nrDns)

	return hosts
}

func parseDnsAddr(addr string) Addr {
	// 223.5.5.5
	if net.ParseIP(addr) != nil {
		return Addr{
			host: addr,
			port: "53",
			udp:  true,
		}
	}
	// dns.google:53
	if host, port, err := net.SplitHostPort(addr); err == nil {
		if _, err = strconv.Atoi(port); err == nil {
			return Addr{
				host: host,
				port: port,
				udp:  true,
			}
		}
	}
	// tcp://8.8.8.8:53, https://dns.google/dns-query, quic://dns.nextdns.io
	if u, err := url.Parse(addr); err == nil {
		udp := false
		if u.Scheme == "quic" {
			udp = true
		}
		return Addr{
			host: u.Hostname(),
			port: u.Port(),
			udp:  udp,
		}
	}
	// dns.google, dns.pub, etc.
	return Addr{
		host: addr,
		port: "53",
		udp:  true,
	}
}

type DnsRouting struct {
	DirectDomains []Addr
	ProxyDomains  []Addr
	DirectIPs     []Addr
	ProxyIPs      []Addr
}

func parseAdvancedDnsServers(lines []string, domains []string) (domainNameServers []interface{}, routing []coreObj.RoutingRule) {
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		dns := ParseAdvancedDnsLine(line)
		if u, err := url.Parse(dns.Val); err == nil &&
			strings.Contains(dns.Val, "://") &&
			!strings.Contains(u.Scheme, "://") {
			// FIXME: after quic:// supported
			if u.Scheme == "quic" {
				u.Scheme = "quic+local"
				dns.Val = u.String()
			}
			// 有 domains 限制则用 ServerObject，否则直接用字符串（文档规范）
			if len(domains) > 0 {
				domainNameServers = append(domainNameServers, coreObj.DnsServer{
					Address: dns.Val,
					Domains: domains,
				})
			} else {
				domainNameServers = append(domainNameServers, dns.Val)
			}
		} else {
			addr := parseDnsAddr(dns.Val)
			p, _ := strconv.Atoi(addr.port)
			if len(domains) > 0 {
				domainNameServers = append(domainNameServers, coreObj.DnsServer{
					Address: addr.host,
					Port:    p,
					Domains: domains,
				})
			} else {
				// IP:port 形式但无 domains：用对象只保留地址和端口
				if p != 0 && p != 53 {
					domainNameServers = append(domainNameServers, coreObj.DnsServer{
						Address: addr.host,
						Port:    p,
					})
				} else {
					domainNameServers = append(domainNameServers, addr.host)
				}
			}
		}

		if dns.Val == "localhost" {
			// no need to routing
			continue
		}
		// we believe all lines are legal
		var addr = parseDnsAddr(dns.Val)

		if net.ParseIP(addr.host) != nil {
			routing = append(routing, coreObj.RoutingRule{
				Type: "field", OutboundTag: dns.Out, IP: []string{addr.host}, Port: addr.port,
			})
		} else {
			routing = append(routing, coreObj.RoutingRule{
				Type: "field", OutboundTag: dns.Out, Domain: []string{addr.host}, Port: addr.port,
			})
		}
	}
	return domainNameServers, routing
}

// outName -> isGroup
func (t *Template) outNames() map[string]bool {
	tags := make(map[string]bool)
	for _, o := range t.Outbounds {
		if len(o.Balancers) > 0 {
			for _, groupName := range o.Balancers {
				tags[groupName] = true
			}
		} else {
			tags[o.Tag] = false
		}
	}
	return tags
}

func (t *Template) FirstProxyOutboundName(filter func(outboundName string, isGroup bool) bool) (outboundName string, isGroup bool) {
	if filter == nil {
		filter = func(outboundName string, isGroup bool) bool {
			return true
		}
	}
	// deduplicate
	m := make(map[string]struct{})

	for _, o := range t.Outbounds {
		switch o.Tag {
		case "direct", "block", "dns-out":
			continue
		}
		if len(o.Balancers) > 0 {
			for _, v := range o.Balancers {
				if _, ok := m[v]; !ok {
					if filter(v, true) {
						return v, true
					}
					m[v] = struct{}{}
				}
			}
		} else {
			if filter(o.Tag, false) {
				return o.Tag, false
			}
		}
	}
	return
}

func (t *Template) setDNS(outbounds []serverInfo, supportUDP map[string]bool) (routing []coreObj.RoutingRule, err error) {
	firstOutboundTag, _ := t.FirstProxyOutboundName(nil)

	// 解析 DNS 查询策略
	queryStrategy := string(t.Setting.DnsMode)
	if queryStrategy == "" {
		queryStrategy = string(configure.DnsQueryStrategyUseIP)
	}

	t.DNS = &coreObj.DNS{
		Tag:           "dns",
		QueryStrategy: queryStrategy,
	}

	// 使用用户自定义的 DNS 服务器列表
	// 复制一份，避免排序污染原始设置
	dnsEntries := make([]configure.DnsServerEntry, len(t.Setting.DnsServers))
	copy(dnsEntries, t.Setting.DnsServers)
	// 无 domains 的服务器（兜底）排在前面，有 domains 的server排在后面
	// v2fly DNS：domain-specific 服务器在命中域名时优先，但'兜底服务器'需要是整个列表中
	// 第一个无 domains 限制的条目，因此必须确保兜底条目不被排在 domain-specific 条目之后遮蔽。
	sort.SliceStable(dnsEntries, func(i, j int) bool {
		return len(dnsEntries[i].Domains) == 0 && len(dnsEntries[j].Domains) > 0
	})
	if len(dnsEntries) == 0 {
		// 降级默认：仅使用 localhost
		t.DNS.Servers = []interface{}{"localhost"}
	} else {
		for _, entry := range dnsEntries {
			if entry.Address == "" {
				continue
			}
			// 确定出站 tag
			outTag := entry.Outbound
			if outTag == "proxy" {
				// 使用第一个代理出站
				outTag = firstOutboundTag
			}
			if outTag == "" {
				outTag = "direct"
			}

			if len(entry.Domains) == 0 {
				// 无 domains 限制时直接用字符串，符合 v2fly DNS 文档规范
				// https://www.v2fly.org/config/dns.html#dnsobject
				t.DNS.Servers = append(t.DNS.Servers, entry.Address)
			} else {
				t.DNS.Servers = append(t.DNS.Servers, coreObj.DnsServer{
					Address: entry.Address,
					Domains: entry.Domains,
				})
			}

			// 为该 DNS 服务器的流量生成路由规则（localhost 不需要路由）
			if entry.Address == "localhost" {
				continue
			}
			addr := parseDnsAddr(entry.Address)
			if addr.host == "" {
				continue
			}
			if net.ParseIP(addr.host) != nil {
				routing = append(routing, coreObj.RoutingRule{
					Type: "field", OutboundTag: outTag, IP: []string{addr.host}, Port: addr.port,
				})
			} else {
				routing = append(routing, coreObj.RoutingRule{
					Type: "field", OutboundTag: outTag, Domain: []string{addr.host}, Port: addr.port,
				})
			}
		}
	}

	// 收集需要 DNS 预解析的域名（出站服务器域名 + DNS 服务器本身的域名）
	var domainsToLookup []string
	for _, v := range outbounds {
		if net.ParseIP(v.Info.GetHostname()) == nil {
			domainsToLookup = append(domainsToLookup, v.Info.GetHostname())
		}
	}
	for _, srv := range t.DNS.Servers {
		var dnsAddr string
		switch s := srv.(type) {
		case string:
			dnsAddr = s
		case coreObj.DnsServer:
			dnsAddr = s.Address
		}
		if dnsAddr == "" || dnsAddr == "localhost" || dnsAddr == "fakedns" {
			continue
		}
		addr := parseDnsAddr(dnsAddr)
		if net.ParseIP(addr.host) == nil {
			domainsToLookup = append(domainsToLookup, addr.host)
		}
	}
	domainsToLookup = common.Deduplicate(domainsToLookup)
	if len(domainsToLookup) > 0 {
		// 优先使用用户配置的节点解析 DNS；若留空则回退到内置默认
		nodeResolveDns := t.Setting.NodeResolveDns
		if nodeResolveDns == "" {
			nodeResolveDns = "https://223.5.5.5/dns-query"
		}
		// 校验：nodeResolveDns 的主机部分必须是 IP，不得是域名（循环依赖）
		nrAddr := parseDnsAddr(nodeResolveDns)
		if net.ParseIP(nrAddr.host) == nil {
			return nil, fmt.Errorf("nodeResolveDns %q 的主机部分 %q 不是合法 IP 地址；"+
				"请使用 IP 地址，例如 https://223.5.5.5/dns-query，避免循环解析依赖", nodeResolveDns, nrAddr.host)
		}
		bootstrapList := []string{
			nodeResolveDns + " -> direct",
		}
		d, r := parseAdvancedDnsServers(bootstrapList, domainsToLookup)
		t.DNS.Servers = append(t.DNS.Servers, d...)
		routing = append(routing, r...)
	}

	// 硬编码 Apple Push 的 SNI 修复 (#495 #479)
	t.DNS.Hosts = make(coreObj.Hosts)
	t.DNS.Hosts["courier.push.apple.com"] = []string{"1-courier.push.apple.com"}

	// 去重路由规则
	strRouting := make([]string, 0, len(routing))
	for _, r := range routing {
		b, err := jsoniter.Marshal(r)
		if err != nil {
			return nil, fmt.Errorf("jsoniter.Marshal: %v", err)
		}
		strRouting = append(strRouting, string(b))
	}
	strRouting = common.Deduplicate(strRouting)
	routing = routing[:0]
	for _, sr := range strRouting {
		var r coreObj.RoutingRule
		if err := jsoniter.Unmarshal([]byte(sr), &r); err != nil {
			return nil, fmt.Errorf("jsoniter.Unmarshal: RoutingRule: %v", err)
		}
		routing = append(routing, r)
	}
	return routing, nil
}

// FilterIPs returns filtered IP list.
// The order are from v4 IPs to v6 IPs.
// If the system does not support IPv6, v6 IPs will not be returned.
func FilterIPs(ips []string) []string {
	var ret []string
	for _, ip := range ips {
		if net.ParseIP(ip).To4() != nil {
			ret = append(ret, ip)
		}
	}
	if !iptables.IsIPv6Supported() {
		return ret
	}
	for _, ip := range ips {
		if net.ParseIP(ip).To4() == nil {
			ret = append(ret, ip)
		}
	}
	return ret
}
func (t *Template) setDNSRouting(routing []coreObj.RoutingRule, supportUDP map[string]bool) {
	firstOutboundTag, _ := t.FirstProxyOutboundName(nil)
	t.Routing.Rules = append(t.Routing.Rules, routing...)
	t.Routing.Rules = append(t.Routing.Rules,
		coreObj.RoutingRule{Type: "field", InboundTag: []string{"dns-in"}, OutboundTag: "direct"},
	)
	// 始终将 TUN/Redirect/TProxy 的 dokodemo-door DNS 入站（tun-dns-in，端口 6053）转发到 dns-out
	t.Routing.Rules = append(t.Routing.Rules,
		coreObj.RoutingRule{Type: "field", InboundTag: []string{"tun-dns-in"}, OutboundTag: "dns-out"},
		coreObj.RoutingRule{Type: "field", Port: strconv.Itoa(tun.TunDNSListenPort), OutboundTag: "dns-out"},
	)
	setting := t.Setting
	// 将 53 端口的 DNS 查询劫持到 dns-out（始终开启，配合新 DNS 模块）
	{
		dnsOut := coreObj.RoutingRule{
			Type:        "field",
			Port:        "53",
			OutboundTag: "dns-out",
		}
		inTags := []string{"tun-dns-in"}
		dnsOut.InboundTag = inTags
		t.Routing.Rules = append(t.Routing.Rules, dnsOut)
	}
	if !supportUDP[firstOutboundTag] {
		// find an outbound that supports UDP and redirect all leaky UDP traffic to it
		var found bool
		for outbound, support := range supportUDP {
			if support {
				t.Routing.Rules = append(t.Routing.Rules,
					coreObj.RoutingRule{
						Type:        "field",
						OutboundTag: outbound,
						Network:     "udp",
					},
				)
				found = true
				break
			}
		}
		if !found {
			// no outbound with UDP supported, so redirect all leaky UDP traffic to outbound direct
			t.Routing.Rules = append(t.Routing.Rules,
				coreObj.RoutingRule{
					Type:        "field",
					OutboundTag: "direct",
					Network:     "udp",
				},
			)
		}
	} else {
		if IsTransparentOn(setting) {
			t.Routing.Rules = append(t.Routing.Rules,
				coreObj.RoutingRule{
					Type:        "field",
					OutboundTag: "direct",
					InboundTag: []string{
						"transparent",
					},
					Port: "53",
					IP:   []string{"geoip:private"},
				})
		}
	}
	return
}

func (t *Template) AppendRoutingRuleByMode(mode configure.RulePortMode, inbounds []string) (err error) {
	firstOutboundTag, _ := t.FirstProxyOutboundName(nil)
	// apple pushing. #495 #479
	t.Routing.Rules = append(t.Routing.Rules, coreObj.RoutingRule{
		Type:        "field",
		OutboundTag: "direct",
		InboundTag:  deepcopy.Copy(inbounds).([]string),
		Domain:      []string{"domain:push-apple.com.akadns.net", "domain:push.apple.com"},
	})
	switch mode {
	case configure.WhitelistMode:
		// foreign domains with intranet IP should be proxied first rather than directly connected
		if asset.DoesV2rayAssetExist("LoyalsoldierSite.dat") {
			t.Routing.Rules = append(t.Routing.Rules,
				coreObj.RoutingRule{
					Type:        "field",
					OutboundTag: firstOutboundTag,
					InboundTag:  deepcopy.Copy(inbounds).([]string),
					Domain:      []string{"ext:LoyalsoldierSite.dat:geolocation-!cn"},
				})
		} else {
			t.Routing.Rules = append(t.Routing.Rules,
				coreObj.RoutingRule{
					Type:        "field",
					OutboundTag: firstOutboundTag,
					InboundTag:  deepcopy.Copy(inbounds).([]string),
					Domain:      []string{"geosite:geolocation-!cn"},
				})
		}
		t.Routing.Rules = append(t.Routing.Rules,
			coreObj.RoutingRule{
				Type:        "field",
				OutboundTag: "proxy",
				InboundTag:  deepcopy.Copy(inbounds).([]string),
				// https://github.com/v2rayA/v2rayA/issues/285
				Domain: []string{"geosite:google"},
			},
			coreObj.RoutingRule{
				Type:        "field",
				OutboundTag: "direct",
				InboundTag:  deepcopy.Copy(inbounds).([]string),
				Domain:      []string{"geosite:cn"},
			},
			coreObj.RoutingRule{
				Type:        "field",
				OutboundTag: "proxy",
				InboundTag:  deepcopy.Copy(inbounds).([]string),
				IP:          []string{"geoip:hk", "geoip:mo"},
			},
			coreObj.RoutingRule{
				Type:        "field",
				OutboundTag: "direct",
				InboundTag:  deepcopy.Copy(inbounds).([]string),
				IP:          []string{"geoip:private", "geoip:cn"},
			},
		)
	case configure.GfwlistMode:
		if asset.DoesV2rayAssetExist("LoyalsoldierSite.dat") {
			t.Routing.Rules = append(t.Routing.Rules,
				coreObj.RoutingRule{
					Type:        "field",
					OutboundTag: firstOutboundTag,
					InboundTag:  deepcopy.Copy(inbounds).([]string),
					Domain:      []string{"ext:LoyalsoldierSite.dat:gfw"},
				},
				coreObj.RoutingRule{
					Type:        "field",
					OutboundTag: firstOutboundTag,
					InboundTag:  deepcopy.Copy(inbounds).([]string),
					Domain:      []string{"ext:LoyalsoldierSite.dat:greatfire"},
				})
		} else {
			t.Routing.Rules = append(t.Routing.Rules,
				coreObj.RoutingRule{
					Type:        "field",
					OutboundTag: firstOutboundTag,
					InboundTag:  deepcopy.Copy(inbounds).([]string),
					Domain:      []string{"geosite:geolocation-!cn"},
				})
		}

		t.Routing.Rules = append(t.Routing.Rules,
			coreObj.RoutingRule{
				Type:        "field",
				OutboundTag: firstOutboundTag,
				InboundTag:  deepcopy.Copy(inbounds).([]string),
				// From: https://github.com/Loyalsoldier/geoip/blob/release/text/telegram.txt
				IP: []string{"91.105.192.0/23", "91.108.4.0/22", "91.108.8.0/21", "91.108.16.0/21", "91.108.56.0/22",
					"95.161.64.0/20", "149.154.160.0/20", "185.76.151.0/24", "2001:67c:4e8::/48", "2001:b28:f23c::/47",
					"2001:b28:f23f::/48", "2a0a:f280:203::/48"},
			},
			coreObj.RoutingRule{
				Type:        "field",
				OutboundTag: "direct",
				InboundTag:  deepcopy.Copy(inbounds).([]string),
			},
		)
	case configure.RoutingAMode:
		if err := parseRoutingA(t, deepcopy.Copy(inbounds).([]string)); err != nil {
			return err
		}
	}
	return nil
}

func (t *Template) setRulePortRouting() error {
	// append rule-http and rule-socks no mather if they are enabled
	// because "The Same as the Rule Port" may need them
	return t.AppendRoutingRuleByMode(t.Setting.RulePortMode, []string{"rule-http", "rule-socks"})
}
func parseRoutingA(t *Template, routingInboundTags []string) error {
	lines := strings.Split(configure.GetRoutingA(), "\n")
	hardcodeReplacement := regexp.MustCompile(`\$\$.+?\$\$`)
	for i := range lines {
		hardcodes := hardcodeReplacement.FindAllString(lines[i], -1)
		for _, hardcode := range hardcodes {
			env := strings.TrimSuffix(strings.TrimPrefix(hardcode, "$$"), "$$")
			val, ok := os.LookupEnv(env)
			if !ok {
				log.Error("RoutingA: Environment variable \"%v\" is not found", env)
			} else {
				log.Info("RoutingA: Environment variable %v=%v", env, strconv.Quote(val))
			}
			lines[i] = strings.Replace(lines[i], hardcode, val, 1)
		}
	}
	rules, err := RoutingA.Parse(strings.Join(lines, "\n"))
	if err != nil {
		log.Warn("parseRoutingA: %v", err)
		return err
	}
	defaultOutbound, _ := t.FirstProxyOutboundName(nil)
	for _, rule := range rules {
		switch rule := rule.(type) {
		case RoutingA.Define:
			switch rule.Name {
			case "inbound", "outbound":
				switch o := rule.Value.(type) {
				case RoutingA.Bound:
					proto := o.Value
					switch proto.Name {
					case "http", "socks":
						if len(proto.NamedParams["address"]) < 1 ||
							len(proto.NamedParams["port"]) < 1 {
							continue
						}
						port, err := strconv.Atoi(proto.NamedParams["port"][0])
						if err != nil {
							continue
						}
						server := coreObj.Server{
							Port:    port,
							Address: proto.NamedParams["address"][0],
						}
						if unames := proto.NamedParams["user"]; len(unames) > 0 {
							passwords := proto.NamedParams["pass"]
							levels := proto.NamedParams["level"]
							for i, uname := range unames {
								u := coreObj.OutboundUser{
									User: uname,
								}
								if i < len(passwords) {
									u.Pass = passwords[i]
								}
								if i < len(levels) {
									level, err := strconv.Atoi(levels[i])
									if err == nil {
										u.Level = level
									}
								}
								server.Users = append(server.Users, u)
							}
						}
						switch rule.Name {
						case "outbound":
							t.Outbounds = append(t.Outbounds, coreObj.OutboundObject{
								Tag:      o.Name,
								Protocol: o.Value.Name,
								Settings: coreObj.Settings{
									Servers: []coreObj.Server{
										server,
									},
								},
							})
						case "inbound":
							// reform from outbound
							in := coreObj.Inbound{
								Tag:      o.Name,
								Protocol: o.Value.Name,
								Listen:   server.Address,
								Port:     server.Port,
								Settings: &coreObj.InboundSettings{
									UDP: false,
								},
								Sniffing: coreObj.Sniffing{
									Enabled:      false,
									DestOverride: []string{"http", "tls"},
									RouteOnly:    false,
								},
							}
							if sniffing := proto.NamedParams["sniffing"]; len(sniffing) > 0 {
								// support inbound:a=socks(address: 127.0.0.1, port: 1080, sniffing:tls, sniffing:http)
								// support inbound:a=http(address: 127.0.0.1, port: 1081, sniffing:"http,tls")
								in.Sniffing.Enabled = true
								var sniffs []string
								for _, sniff := range sniffing {
									fields := strings.Split(sniff, ",")
									for i := range fields {
										fields[i] = strings.TrimSpace(fields[i])
									}
									sniffs = append(sniffs, fields...)
								}
								in.Sniffing.DestOverride = sniffs
							}
							if proto.Name == "socks" {
								if len(server.Users) > 0 {
									in.Settings.Auth = "password"
								}
								if udp := proto.NamedParams["udp"]; len(udp) > 0 {
									in.Settings.UDP = udp[0] == "true"
								}
								if userLevels := proto.NamedParams["userLevel"]; len(userLevels) > 0 {
									userLevel, err := strconv.Atoi(userLevels[0])
									if err == nil {
										in.Settings.UserLevel = userLevel
									}
								}
							}
							if len(server.Users) > 0 {
								for _, u := range server.Users {
									in.Settings.Accounts = append(in.Settings.Accounts, coreObj.Account{
										User: u.User,
										Pass: u.Pass,
									})
								}
							}
							t.Inbounds = append(t.Inbounds, in)
							routingInboundTags = append(routingInboundTags, o.Name)
						}
					case "freedom":
						settings := coreObj.Settings{}
						if len(proto.NamedParams["domainStrategy"]) > 0 {
							settings.DomainStrategy = proto.NamedParams["domainStrategy"][0]
						}
						if len(proto.NamedParams["redirect"]) > 0 {
							settings.Redirect = proto.NamedParams["redirect"][0]
						}
						if len(proto.NamedParams["userLevel"]) > 0 {
							level, err := strconv.Atoi(proto.NamedParams["userLevel"][0])
							if err == nil {
								settings.UserLevel = &level
							}
						}
						t.Outbounds = append(t.Outbounds, coreObj.OutboundObject{
							Tag:      o.Name,
							Protocol: o.Value.Name,
							Settings: settings,
						})
					}
				}
			}
		}
	}
	outboundTags := t.outNames()
	for _, rule := range rules {
		switch rule := rule.(type) {
		case RoutingA.Define:
			switch rule.Name {
			case "default":
				switch v := rule.Value.(type) {
				case string:
					defaultOutbound = v
					if _, ok := outboundTags[v]; !ok {
						return fmt.Errorf(`your RoutingA rules depend on the outbound "%v", thus you should select at least one server in this outbound`, v)
					}
				}
			}
		case RoutingA.Routing:
			rr := deepcopy.Copy(coreObj.RoutingRule{
				Type:        "field",
				OutboundTag: rule.Out,
				InboundTag:  routingInboundTags,
			}).(coreObj.RoutingRule)
			for _, f := range rule.And {
				switch f.Name {
				case "domain", "domains":
					for k, vv := range f.NamedParams {
						for _, v := range vv {
							if k == "contains" {
								rr.Domain = append(rr.Domain, v)
								continue
							}
							if k == "ext" {
								datFilenameAndTag := strings.SplitN(v, ":", 2)
								if len(datFilenameAndTag) < 2 {
									return fmt.Errorf("%v: tag is not given", v)
								}
								if !asset.DoesV2rayAssetExist(datFilenameAndTag[0]) {
									return fmt.Errorf("%v: file is not found", datFilenameAndTag[0])
								}
							}
							rr.Domain = append(rr.Domain, fmt.Sprintf("%v:%v", k, v))
						}
					}
					// unnamed param is not recommended
					rr.Domain = append(rr.Domain, f.Params...)
				case "ip":
					for k, vv := range f.NamedParams {
						for _, v := range vv {
							if k == "ext" {
								datFilenameAndTag := strings.SplitN(v, ":", 2)
								if len(datFilenameAndTag) < 2 {
									return fmt.Errorf("%v: tag is not given", v)
								}
								if !asset.DoesV2rayAssetExist(datFilenameAndTag[0]) {
									return fmt.Errorf("%v: file is not found", datFilenameAndTag[0])
								}
							}
							rr.IP = append(rr.IP, fmt.Sprintf("%v:%v", k, v))
						}
					}
					rr.IP = append(rr.IP, f.Params...)
				case "network":
					rr.Network = strings.Join(f.Params, ",")
				case "port":
					rr.Port = strings.Join(f.Params, ",")
				case "sourcePort":
					rr.SourcePort = strings.Join(f.Params, ",")
				case "protocol":
					rr.Protocol = f.Params
				case "source":
					rr.Source = f.Params
				case "user":
					rr.User = f.Params
				case "inboundTag":
					rr.InboundTag = f.Params
				}
			}
			if rr.OutboundTag != "" {
				if _, ok := outboundTags[rr.OutboundTag]; !ok {
					return fmt.Errorf(`your RoutingA rules depend on the outbound "%v", thus you should select at least one server in this outbound`, rr.OutboundTag)
				}
			}
			t.Routing.Rules = append(t.Routing.Rules, rr)
		}
	}
	t.Routing.Rules = append(t.Routing.Rules, coreObj.RoutingRule{
		Type:        "field",
		OutboundTag: defaultOutbound,
		InboundTag:  []string{"rule-http", "rule-socks"},
	})
	return nil
}

func (t *Template) setTransparentRouting() (err error) {
	defaultOutbound, _ := t.FirstProxyOutboundName(nil)
	switch t.Setting.Transparent {
	case configure.TransparentProxy:
		// Global transparent: route all transparent inbound to default outbound
		t.Routing.Rules = append(t.Routing.Rules, coreObj.RoutingRule{
			Type:        "field",
			InboundTag:  []string{"transparent"},
			OutboundTag: defaultOutbound,
		})
	case configure.TransparentWhitelist:
		return t.AppendRoutingRuleByMode(configure.WhitelistMode, []string{"transparent"})
	case configure.TransparentGfwlist:
		return t.AppendRoutingRuleByMode(configure.GfwlistMode, []string{"transparent"})
	case configure.TransparentFollowRule:
		// transparent mode is the same as rule
		for i := range t.Routing.Rules {
			ok := false
			for _, in := range t.Routing.Rules[i].InboundTag {
				if in == "rule-http" {
					ok = true
					break
				}
			}
			if ok {
				t.Routing.Rules[i].InboundTag = append(t.Routing.Rules[i].InboundTag, "transparent")
			}
		}
	}
	return nil
}
func (t *Template) AppendDokodemoTProxy(tproxy string, port int, tag string) {
	dokodemo := coreObj.Inbound{
		Listen:   "0.0.0.0",
		Port:     port,
		Protocol: "dokodemo-door",
		Sniffing: coreObj.Sniffing{
			Enabled:      true,
			DestOverride: []string{"http", "tls"},
		},
		Settings: &coreObj.InboundSettings{Network: "tcp,udp"},
		Tag:      tag,
	}
	dokodemo.StreamSettings = &coreObj.StreamSettings{Sockopt: &coreObj.Sockopt{Tproxy: &tproxy}}
	dokodemo.Settings.FollowRedirect = true
	t.Inbounds = append(t.Inbounds, dokodemo)
}

func (t *Template) SetOutboundSockopt() {
	mark := 0x80
	//tos := 184
	for i := range t.Outbounds {
		if t.Outbounds[i].Protocol == "blackhole" || t.Outbounds[i].Protocol == "dns" {
			continue
		}
		if t.Outbounds[i].StreamSettings == nil {
			t.Outbounds[i].StreamSettings = new(coreObj.StreamSettings)
		}
		if t.Outbounds[i].StreamSettings.Sockopt == nil {
			t.Outbounds[i].StreamSettings.Sockopt = new(coreObj.Sockopt)
		}
		if t.Outbounds[i].Protocol == "freedom" && t.Outbounds[i].Tag == "direct" {
			t.Outbounds[i].Settings.DomainStrategy = "UseIP"
		}
		if t.Setting.TcpFastOpen != configure.Default {
			tmp := t.Setting.TcpFastOpen == configure.Yes
			t.Outbounds[i].StreamSettings.Sockopt.TCPFastOpen = &tmp
		}
		t.checkAndSetMark(&t.Outbounds[i], mark)
	}
}
func (t *Template) setDualStack() {
	const (
		tag4Suffix = "_ipv4"
		tag6Suffix = "_ipv6"
	)
	tagMap := make(map[string]struct{})
	inbounds6 := deepcopy.Copy(t.Inbounds).([]coreObj.Inbound)
	if !t.Setting.PortSharing {
		// copy a group of ipv6 inbounds and set the tag
		for i := range t.Inbounds {
			if t.Inbounds[i].Tag == "transparent" && t.Setting.TransparentType == configure.TransparentRedirect {
				// https://ipset.netfilter.org/iptables-extensions.man.html#lbDK
				// REDIRECT redirects the packet to the machine itself by changing the destination IP to the primary address of the incoming interface.
				// So we should listen at 0.0.0.0 instead of 127.0.0.1
				inbounds6[i].Tag = "THIS_IS_A_DROPPED_TAG"
				continue
			}
			if t.Inbounds[i].Tag == "dns-in" {
				t.Inbounds[i].Listen = "127.2.0.17"
				inbounds6[i].Tag = "THIS_IS_A_DROPPED_TAG"
				continue
			} else {
				t.Inbounds[i].Listen = "127.0.0.1"
			}
			inbounds6[i].Listen = "::1"
			if t.Inbounds[i].Tag != "" {
				tagMap[t.Inbounds[i].Tag] = struct{}{}
				t.Inbounds[i].Tag += tag4Suffix
				inbounds6[i].Tag += tag6Suffix
			}
		}
		for i := len(inbounds6) - 1; i >= 0; i-- {
			if inbounds6[i].Tag == "THIS_IS_A_DROPPED_TAG" {
				inbounds6 = append(inbounds6[:i], inbounds6[i+1:]...)
			}
		}

		if iptables.IsIPv6Supported() {
			t.Inbounds = append(t.Inbounds, inbounds6...)
		}

		// set routing
		for i := range t.Routing.Rules {
			tag6 := make([]string, 0)
			for j, tag := range t.Routing.Rules[i].InboundTag {
				if _, ok := tagMap[tag]; ok {
					t.Routing.Rules[i].InboundTag[j] += tag4Suffix
					tag6 = append(tag6, tag+tag6Suffix)
				}
			}
			if v6supported := iptables.IsIPv6Supported(); len(tag6) > 0 && v6supported {
				t.Routing.Rules[i].InboundTag = append(t.Routing.Rules[i].InboundTag, tag6...)
			}
		}
	} else {
		// specially listen 127.2.0.17
		hasDnsIn := false
		for i := range t.Inbounds {
			if t.Inbounds[i].Tag == "dns-in" {
				// listen both 0.0.0.0 and 127.2.0.17
				localDnsInbound := t.Inbounds[i]
				localDnsInbound.Listen = "127.2.0.17"
				localDnsInbound.Tag = "dns-in-local"
				t.Inbounds = append(t.Inbounds, localDnsInbound)
				hasDnsIn = true
				break
			}
		}
		if hasDnsIn {
			// set routing
			for i := range t.Routing.Rules {
				for _, tag := range t.Routing.Rules[i].InboundTag {
					if tag == "dns-in" {
						t.Routing.Rules[i].InboundTag = append(t.Routing.Rules[i].InboundTag, "dns-in-local")
					}
				}
			}
		}
	}
}
func (t *Template) setInboundFakeDnsDestOverride() {
	// FakeIP via special mode has been removed; TUN FakeIP is handled by TunFakeIP setting.
}

func (t *Template) appendDNSOutbound() {
	t.Outbounds = append(t.Outbounds, coreObj.OutboundObject{
		Tag:      "dns-out",
		Protocol: "dns",
		// DNS outbound without address setting will use the internal DNS module,
		// which respects the DNS servers configured in the dns block (e.g., 8.8.4.4, 180.184.1.1)
		// and applies DNS routing rules properly.
		// See: https://www.v2fly.org/config/protocols/dns.html
	})
}

func (t *Template) setSendThrough() {
	for i := 0; i < len(t.Outbounds); i++ {
		outbound := &t.Outbounds[i]

		// Get server info for this outbound
		sInfo, exists := t.serverInfoMap[outbound.Tag]
		if !exists {
			continue
		}

		// Determine the appropriate local address
		sendThrough := t.getSendThroughForServer(sInfo)
		if sendThrough != "" {
			outbound.SendThrough = sendThrough
			log.Trace("[v2ray] Set sendThrough for %s: %s", outbound.Tag, sendThrough)
		}
	}
}

func (t *Template) getSendThroughForServer(sInfo *serverInfo) string {
	serverHost := sInfo.Info.GetHostname()

	// If connecting to plugin (localhost), use 127.0.0.1
	if sInfo.PluginPort > 0 {
		return "127.0.0.1"
	}

	// Check if server is IPv4 or IPv6
	if serverIP := net.ParseIP(serverHost); serverIP != nil {
		if serverIP.To4() != nil {
			// IPv4 server - use IPv4 local address
			if ip, err := GetBestLocalIP(false); err == nil {
				return ip.String()
			}
		} else {
			// IPv6 server - use IPv6 local address
			if ip, err := GetBestLocalIP(true); err == nil {
				return ip.String()
			}
			// Fallback to link-local IPv6 if no global address available
			if ip, err := GetLinkLocalIPv6(); err == nil {
				return ip.String()
			}
		}
	} else {
		// Domain name - prefer IPv4
		if ip, err := GetBestLocalIP(false); err == nil {
			return ip.String()
		}
	}

	return ""
}

// GetBestLocalIP returns the best local IP address, skipping TUN, loopback, and APIPA addresses
func GetBestLocalIP(preferIPv6 bool) (net.IP, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var bestIP net.IP

	for _, iface := range interfaces {
		// Skip interfaces that are down
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		// Skip TUN interfaces (typically named tun0, utun0, sing-tun, etc.)
		ifName := strings.ToLower(iface.Name)
		if strings.Contains(ifName, "tun") || strings.Contains(ifName, "tap") {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ip := ipnet.IP

			// Skip loopback
			if ip.IsLoopback() {
				continue
			}

			// Skip APIPA (169.254.x.x)
			if ip.To4() != nil && ip.To4()[0] == 169 && ip.To4()[1] == 254 {
				continue
			}

			if preferIPv6 {
				if ip.To4() == nil && ip.To16() != nil {
					// IPv6 address
					// Skip link-local for now (fe80::), prefer global
					if !ip.IsLinkLocalUnicast() {
						return ip, nil
					}
					if bestIP == nil {
						bestIP = ip
					}
				}
			} else {
				if ip.To4() != nil {
					// IPv4 address
					return ip, nil
				}
			}
		}
	}

	if bestIP != nil {
		return bestIP, nil
	}

	if preferIPv6 {
		return nil, errors.New("no suitable IPv6 address found")
	}
	return nil, errors.New("no suitable IPv4 address found")
}

// GetLinkLocalIPv6 returns a link-local IPv6 address as fallback
func GetLinkLocalIPv6() (net.IP, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		// Skip TUN interfaces
		ifName := strings.ToLower(iface.Name)
		if strings.Contains(ifName, "tun") || strings.Contains(ifName, "tap") {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ip := ipnet.IP
			if ip.To4() == nil && ip.To16() != nil && ip.IsLinkLocalUnicast() {
				return ip, nil
			}
		}
	}

	return nil, errors.New("no link-local IPv6 address found")
}

func GenerateIdFromAccounts() (id string, err error) {
	accounts, err := configure.GetAccounts()
	if err != nil {
		return "", err
	}
	sort.Slice(accounts, func(i, j int) bool {
		if accounts[i][0] == accounts[j][0] {
			return accounts[i][1] < accounts[j][1]
		}
		return accounts[i][0] < accounts[j][0]
	})
	h := sha256.New()
	for _, account := range accounts {
		h.Write([]byte(account[0]))
		h.Write([]byte(account[1]))
	}
	id = common.StringToUUID5(hex.EncodeToString(h.Sum(nil)))
	return id, nil
}

func SetVmessInbound(vmess *coreObj.Inbound) (err error) {
	id, err := GenerateIdFromAccounts()
	if err != nil {
		return err
	}
	vmess.Settings.Clients = []coreObj.VlessClient{{Id: id}}
	return nil
}

func (t *Template) setInbound(setting *configure.Setting) error {
	p := configure.GetPortsNotNil()
	if p != nil {
		t.Inbounds[0].Port = p.Socks5
		t.Inbounds[1].Port = p.Http
		t.Inbounds[2].Port = p.Socks5WithPac
		t.Inbounds[3].Port = p.HttpWithPac
		vmess := &t.Inbounds[4]
		vmess.Port = p.Vmess
		if p.Vmess > 0 {
			if err := SetVmessInbound(vmess); err != nil {
				return err
			}
		}
	}
	// remove those inbounds with zero port number
	for i := len(t.Inbounds) - 1; i >= 0; i-- {
		if t.Inbounds[i].Port == 0 {
			t.Inbounds = append(t.Inbounds[:i], t.Inbounds[i+1:]...)
		}
	}
	if IsTransparentOn(t.Setting) {
		switch t.Setting.TransparentType {
		case configure.TransparentTproxy, configure.TransparentRedirect:
			t.AppendDokodemoTProxy(string(t.Setting.TransparentType), 52345, "transparent")
			// 在 Redirect/TProxy 模式下也添加 6053 端口的任意门入站，用于接收 DNS 查询
			t.Inbounds = append(t.Inbounds, coreObj.Inbound{
				Port:     tun.TunDNSListenPort,
				Protocol: "dokodemo-door",
				Listen:   "0.0.0.0",
				Settings: &coreObj.InboundSettings{
					Network: "tcp,udp",
					Address: "8.8.8.8",
					Port:    53,
				},
				Tag: "tun-dns-in",
			})
		case configure.TransparentGvisorTun, configure.TransparentSystemTun:
			t.Inbounds = append(t.Inbounds, coreObj.Inbound{
				Port:     52345,
				Protocol: "socks",
				Listen:   "127.0.0.1",
				Settings: &coreObj.InboundSettings{
					UDP: true,
				},
				Tag: "transparent",
			})
			// Local dokodemo-door listener for DNS (used by TUN DNS forwarder)
			// Listen on localhost (dual-stack: IPv4 + IPv6)
			t.Inbounds = append(t.Inbounds, coreObj.Inbound{
				Port:     tun.TunDNSListenPort,
				Protocol: "dokodemo-door",
				Listen:   "localhost",
				Settings: &coreObj.InboundSettings{
					Network: "tcp,udp",
					Address: "127.0.0.1",
					Port:    53,
				},
				Tag: "tun-dns-in",
			})
		case configure.TransparentSystemProxy:
			t.Inbounds = append(t.Inbounds, coreObj.Inbound{
				Port:     52345,
				Protocol: "http",
				Listen:   "127.0.0.1",
				Tag:      "transparent",
			}, coreObj.Inbound{
				Port:     52306,
				Protocol: "socks",
				Listen:   "127.0.0.1",
				Settings: &coreObj.InboundSettings{
					UDP: true,
				},
				Tag: "transparent-socks",
			})
		}

	}
	if setting.Transparent != configure.TransparentClose &&
		setting.TransparentType == configure.TransparentRedirect &&
		!conf.GetEnvironmentConfig().Lite {
		// set up a solo dokodemo-door for dns for redirect mode
		t.Inbounds = append(t.Inbounds, coreObj.Inbound{
			Port:     53,
			Protocol: "dokodemo-door",
			Listen:   "0.0.0.0",
			Settings: &coreObj.InboundSettings{
				Network: "udp",
				// the non-A/AAAA/CNAME problem has been fixed by the setting in DNS outbound.
				// so the Address here is innocuous.
				// related commit: https://github.com/v2rayA/v2rayA/commit/ecbf915d4be8b9066955a21059519266bcca6b92
				Address: "2.0.1.7",
				Port:    53,
			},
			Tag: "dns-in",
		})
	}

	// 设置域名嗅探
	if setting.InboundSniffing != configure.InboundSniffingDisable && setting.InboundSniffing != "" {
		enableSniffingRouteOnly := configure.GetSettingNotNil().RouteOnly
		domainsExcludedText := configure.GetDomainsExcluded()
		for i := len(t.Inbounds) - 1; i >= 0; i-- {
			if setting.InboundSniffing == configure.InboundSniffingHttpTLS {
				t.Inbounds[i].Sniffing.DestOverride = []string{"http", "tls"}
			} else {
				t.Inbounds[i].Sniffing.DestOverride = []string{"http", "tls", "quic"}
			}
			t.Inbounds[i].Sniffing.DomainsExcluded = strings.Split(domainsExcludedText, "\n")
			t.Inbounds[i].Sniffing.Enabled = true
			t.Inbounds[i].Sniffing.RouteOnly = enableSniffingRouteOnly
		}

	}
	return nil
}

type serverInfo struct {
	Info         serverObj.ServerObj
	OutboundName string
	PluginPort   int
}

func GroupWrapper(ps string) string {
	return fmt.Sprintf("『%v』", ps)
}

func (t *Template) updatePrivateRouting() {
	privateAddrs, _ := iptables.GetLocalCIDR()
	if len(privateAddrs) == 0 {
		return
	}
	for i := range t.Routing.Rules {
		for j := range t.Routing.Rules[i].IP {
			if t.Routing.Rules[i].IP[j] == "geoip:private" {
				t.Routing.Rules[i].IP = append(t.Routing.Rules[i].IP, privateAddrs...)
				break
			}
		}
	}
}

func (t *Template) optimizeGeoipMemoryOccupation() {
	if asset.DoesV2rayAssetExist("geoip-only-cn-private.dat") {
		for i := range t.Routing.Rules {
			for j := range t.Routing.Rules[i].IP {
				switch t.Routing.Rules[i].IP[j] {
				case "geoip:private", "geoip:cn":
					t.Routing.Rules[i].IP[j] = "ext:geoip-only-cn-private.dat:" + strings.TrimPrefix(t.Routing.Rules[i].IP[j], "geoip:")
				}
			}
		}
	}
}

func (t *Template) setWhitelistRouting(whitelist []Addr) {
	var rules []coreObj.RoutingRule
	for _, addr := range whitelist {
		if net.ParseIP(addr.host) != nil {
			rules = append(rules, coreObj.RoutingRule{
				Type:        "field",
				OutboundTag: "direct",
				IP:          []string{addr.host},
				Port:        addr.port,
			})
		} else {
			rules = append(rules, coreObj.RoutingRule{
				Type:        "field",
				OutboundTag: "direct",
				Domain:      []string{addr.host},
				Port:        addr.port,
			})
		}
	}
	if len(rules) > 0 {
		t.Routing.Rules = append(rules, t.Routing.Rules...)
	}
}

func (t *Template) setGroupRouting() {
	outbounds := t.outNames()
	for i := range t.Routing.Rules {
		if t.Routing.Rules[i].OutboundTag != "" && outbounds[t.Routing.Rules[i].OutboundTag] == true {
			t.Routing.Rules[i].BalancerTag, t.Routing.Rules[i].OutboundTag = t.Routing.Rules[i].OutboundTag, ""
		}
	}
}

type ServerData struct {
	RawServerInfos          []serverInfo
	ServerInfos             []serverInfo
	OutboundName2Setting    map[string]configure.OutboundSetting
	Link2ServerInfos        map[string][]*serverInfo
	Link2ServerObj          map[string]serverObj.ServerObj
	OutboundName2ServerObjs map[string][]serverObj.ServerObj
}

func NewServerData(serverInfos []serverInfo) (serverData *ServerData) {
	// guarantee that an v2ray outbound is reusable for balancers
	var rawServerInfos = make([]serverInfo, len(serverInfos))
	copy(rawServerInfos, serverInfos)
	link2ServerInfos := make(map[string][]*serverInfo)
	link2ServerObj := make(map[string]serverObj.ServerObj)
	for i, info := range serverInfos {
		link := info.Info.ExportToURL()
		link2ServerObj[link] = info.Info
		link2ServerInfos[link] = append(link2ServerInfos[link], &serverInfos[i])
	}
	// make ps unique
	link2ServerInfosAfter := make(map[string][]*serverInfo)
	mPsRenaming := make(map[string]struct{})
	for link, ois := range link2ServerInfos {
		ps := link2ServerObj[link].GetName()
		cnt := 2
		for {
			if _, ok := mPsRenaming[ps]; !ok {
				mPsRenaming[ps] = struct{}{}
				link2ServerObj[link].SetName(ps)
				link2ServerInfosAfter[link] = ois
				break
			}
			ps = fmt.Sprintf("%v(%v)", link2ServerObj[link].GetName(), strconv.Itoa(cnt))
			cnt++
		}
	}

	outboundName2ServerObjs := make(map[string][]serverObj.ServerObj)
	for link, ois := range link2ServerInfosAfter {
		for _, oi := range ois {
			outboundName2ServerObjs[oi.OutboundName] = append(outboundName2ServerObjs[oi.OutboundName], link2ServerObj[link])
		}
	}

	OutboundName2Setting := make(map[string]configure.OutboundSetting)
	for outbound := range outboundName2ServerObjs {
		OutboundName2Setting[outbound] = configure.GetOutboundSetting(outbound)
	}

	return &ServerData{
		RawServerInfos:          rawServerInfos,
		ServerInfos:             serverInfos,
		Link2ServerInfos:        link2ServerInfosAfter,
		Link2ServerObj:          link2ServerObj,
		OutboundName2ServerObjs: outboundName2ServerObjs,
		OutboundName2Setting:    OutboundName2Setting,
	}
}

func (sd *ServerData) ServerObj2ServerInfos() map[serverObj.ServerObj][]*serverInfo {
	m := make(map[serverObj.ServerObj][]*serverInfo)
	for link, sObj := range sd.Link2ServerObj {
		m[sObj] = sd.Link2ServerInfos[link]
	}
	return m
}

func (sd *ServerData) Ps2OutboundNames() map[string][]string {
	ps2OutboundNames := make(map[string][]string)
	for outboundName, objs := range sd.OutboundName2ServerObjs {
		for _, vi := range objs {
			ps2OutboundNames[vi.GetName()] = append(ps2OutboundNames[vi.GetName()], outboundName)
		}
	}
	return ps2OutboundNames
}

func (t *Template) resolveOutbounds(
	serverData *ServerData,
) (supportUDP map[string]bool, outboundTags []string, err error) {

	supportUDP = make(map[string]bool)
	t.serverInfoMap = make(map[string]*serverInfo)
	type _outbound struct {
		weight   int
		outbound coreObj.OutboundObject
		balancer bool
		plugin   plugin.Server
	}
	serverInfo2Index := make(map[*serverInfo]int)
	for i := range serverData.ServerInfos {
		serverInfo2Index[&serverData.ServerInfos[i]] = i
	}
	// keep order with serverInfos
	outboundTags = make([]string, len(serverData.ServerInfos))
	var extraOutbounds []coreObj.OutboundObject
	var outbounds []_outbound
	for obj, sInfos := range serverData.ServerObj2ServerInfos() {
		var (
			usedByBalancer     bool
			balancerPluginPort int
		)
		// an vmessInfo(server template) may be used by multiple serverInfos(a connected server)

		// outbound name is not just v2ray outbound tag, it may be a balancer
		type balancer struct {
			name       string
			serverInfo *serverInfo
		}
		var balancers []balancer
		for _, sInfo := range sInfos {
			if len(serverData.OutboundName2ServerObjs[sInfo.OutboundName]) > 1 {
				// balancer
				if !usedByBalancer {
					usedByBalancer = true
					balancerPluginPort = sInfo.PluginPort
				}
				balancers = append(balancers, balancer{
					name:       sInfo.OutboundName,
					serverInfo: sInfo,
				})
			} else {
				// pure outbound
				outboundTag := sInfo.OutboundName
				c, err := obj.Configuration(serverObj.PriorInfo{
					Variant:     t.Variant,
					CoreVersion: t.CoreVersion,
					Tag:         outboundTag,
					PluginPort:  sInfo.PluginPort,
				})
				if err != nil {
					return nil, nil, err
				}
				// Store server info for this outbound
				t.serverInfoMap[outboundTag] = sInfo
				extraOutbounds = append(extraOutbounds, c.ExtraOutbounds...)
				if c.PluginManagerServerLink != "" {
					t.PluginManagerInfoList = append(t.PluginManagerInfoList, PluginManagerInfo{
						Link: c.PluginManagerServerLink,
						Port: sInfo.PluginPort,
					})
				}
				var s plugin.Server
				if len(c.PluginChain) > 0 {
					s, err = plugin.ServerFromChain(c.PluginChain, sInfo.Info.GetName())
					if err != nil {
						return nil, nil, err
					}
				}
				outbounds = append(outbounds, _outbound{
					weight:   serverInfo2Index[sInfo],
					outbound: c.CoreOutbound,
					balancer: false,
					plugin:   s,
				})
				outboundTags[serverInfo2Index[sInfo]] = outboundTag
				supportUDP[sInfo.OutboundName] = c.UDPSupport
			}
		}
		if usedByBalancer {
			// the v2ray outbound is shared by balancers
			outboundTag := GroupWrapper(obj.GetName())
			c, err := obj.Configuration(serverObj.PriorInfo{
				Variant:     t.Variant,
				CoreVersion: t.CoreVersion,
				Tag:         outboundTag,
				PluginPort:  balancerPluginPort,
			})
			if err != nil {
				// Store server info for balancer outbound (use first balancer's info)
				if len(balancers) > 0 {
					t.serverInfoMap[outboundTag] = balancers[0].serverInfo
				}
				return nil, nil, err
			}
			extraOutbounds = append(extraOutbounds, c.ExtraOutbounds...)
			for _, v := range balancers {
				c.CoreOutbound.Balancers = append(c.CoreOutbound.Balancers, v.name)
			}
			if c.PluginManagerServerLink != "" {
				t.PluginManagerInfoList = append(t.PluginManagerInfoList, PluginManagerInfo{
					Link: c.PluginManagerServerLink,
					Port: balancerPluginPort,
				})
			}
			// we use the lowest serverInfo index as the order weight of the balancer outbound
			weight := -1
			for _, v := range balancers {
				index := serverInfo2Index[v.serverInfo]
				if weight == -1 || weight > index {
					weight = index
				}
				// tag
				outboundTags[index] = outboundTag
			}
			var s plugin.Server
			if len(c.PluginChain) > 0 {
				s, err = plugin.ServerFromChain(c.PluginChain, obj.GetName())
				if err != nil {
					return nil, nil, err
				}
			}
			outbounds = append(outbounds, _outbound{
				weight:   weight,
				outbound: c.CoreOutbound,
				balancer: true,
				plugin:   s,
			})

			// if any node does not support UDP, the outbound should be tagged as UDP unsupported
			for _, outboundName := range c.CoreOutbound.Balancers {
				_supportUDP := c.UDPSupport
				if _, ok := supportUDP[outboundName]; !ok {
					supportUDP[outboundName] = _supportUDP
				}
				if supportUDP[outboundName] && !_supportUDP {
					supportUDP[outboundName] = false
				}
			}
		}
	}
	sort.Slice(outbounds, func(i, j int) bool {
		return outbounds[i].weight < outbounds[j].weight
	})
	for _, v := range outbounds {
		if v.plugin != nil {
			t.Plugins = append(t.Plugins, v.plugin)
		}
		t.Outbounds = append(t.Outbounds, v.outbound)
	}
	t.Outbounds = append(t.Outbounds, coreObj.OutboundObject{
		Tag:      "direct",
		Protocol: "freedom",
	}, coreObj.OutboundObject{
		Tag:      "block",
		Protocol: "blackhole",
	})
	t.Outbounds = append(t.Outbounds, extraOutbounds...)
	return supportUDP, outboundTags, nil
}

func (t *Template) SetAPI(serverData *ServerData) (port int, err error) {
	// find a valid port
	config := configure.GetPortsNotNil()
	if config.Api.Port != 0 {
		port = config.Api.Port
	} else {
		for {
			if l, err := net.Listen("tcp4", "127.0.0.1:0"); err == nil {
				port = l.Addr().(*net.TCPAddr).Port
				_ = l.Close()
				break
			}
			time.Sleep(30 * time.Millisecond)
		}
	}
	services := []string{
		"LoggerService",
	}
	services = slicex.Uniq(append(services, config.Api.Services...))
	// observatory
	if serverData != nil {
		outbounds := t.outNames()
		for outbound, isGroup := range outbounds {
			if !isGroup {
				continue
			}

			//TODO: random, leastload
			strategy := serverData.OutboundName2Setting[outbound].Type
			interval, err := time.ParseDuration(serverData.OutboundName2Setting[outbound].ProbeInterval)
			if err != nil {
				log.Warn("observatory: %v", err)
				interval = 10 * time.Second
			}
			var selector []string

			for _, vi := range serverData.OutboundName2ServerObjs[outbound] {
				selector = append(selector, GroupWrapper(vi.GetName()))
			}

			t.Routing.Balancers = append(t.Routing.Balancers, coreObj.Balancer{
				Tag:      outbound,
				Selector: selector,
				Strategy: coreObj.BalancerStrategy{
					Type: strategy.String(),
					Settings: &coreObj.StrategySettings{
						ObserverTag: outbound,
					},
				},
			})

			if strings.ToLower(strategy.String()) == "leastping" {
				probeUrl := serverData.OutboundName2Setting[outbound].ProbeURL
				if _, err := url.Parse(probeUrl); err != nil {
					log.Warn("observatory: %v", err)
					probeUrl = "https://gstatic.com/generate_204"
				}

				// Use different observatory structure based on core type
				if t.Variant == where.Xray {
					// Xray uses a single observatory with all selectors combined
					if t.Observatory == nil {
						t.Observatory = &coreObj.ObservatoryItem{
							Tag: "observatory",
							Settings: coreObj.Observatory{
								SubjectSelector: selector,
								ProbeURL:        probeUrl,
								ProbeInterval:   interval.String(),
							},
						}
					} else {
						// Merge selectors for existing observatory
						t.Observatory.Settings.SubjectSelector = append(t.Observatory.Settings.SubjectSelector, selector...)
					}
				} else {
					// V2ray uses multiObservatory with multiple observers
					if t.MultiObservatory == nil {
						t.MultiObservatory = &coreObj.MultiObservatory{}
					}
					t.MultiObservatory.Observers = append(t.MultiObservatory.Observers, coreObj.ObservatoryItem{
						Tag: outbound,
						Settings: coreObj.Observatory{
							SubjectSelector: selector,
							ProbeURL:        probeUrl,
							ProbeInterval:   interval.String(),
						},
					})
				}
			}
		}
		if t.MultiObservatory != nil || t.Observatory != nil {
			// Observatory API is only available in v2ray-core v5+
			// xray-core has different API structure and doesn't support this gRPC service
			if t.Variant == where.V2ray {
				services = append(services, "ObservatoryService")

				var observatoryTags []string
				for name, isGroup := range t.outNames() {
					if isGroup {
						observatoryTags = append(observatoryTags, name)
					}
				}
				t.ApiCloses = append(t.ApiCloses, ObservatoryProducer(port, observatoryTags))
			}
		}
	}
	t.API = &coreObj.APIObject{
		Tag:      "api-out",
		Services: services,
	}

	t.Inbounds = append(t.Inbounds, coreObj.Inbound{
		Port:     port,
		Protocol: "dokodemo-door",
		Listen:   "127.0.0.1",
		Settings: &coreObj.InboundSettings{
			Address: "127.0.0.1",
		},
		Tag: "api-in",
	})
	t.Routing.Rules = append(t.Routing.Rules, coreObj.RoutingRule{
		Type:        "field",
		InboundTag:  []string{"api-in"},
		OutboundTag: "api-out",
	})
	t.ApiPort = port
	return port, nil
}

func (t *Template) setVmessInboundRouting() {
	if configure.GetPortsNotNil().Vmess <= 0 {
		return
	}
	for i := range t.Routing.Rules {
		var bHasRule bool
		for _, tag := range t.Routing.Rules[i].InboundTag {
			if tag == "rule-http" {
				bHasRule = true
			}
		}
		if bHasRule {
			t.Routing.Rules[i].InboundTag = append(t.Routing.Rules[i].InboundTag, "vmess")
		}
	}
}

func NewTemplate(serverInfos []serverInfo, setting *configure.Setting) (t *Template, err error) {
	serverData := NewServerData(serverInfos)
	if setting != nil {
		setting.FillEmpty()
	} else {
		setting = configure.GetSettingNotNil()
	}

	var tmplJson Template
	// read template json
	raw := []byte(TemplateJson)
	err = jsoniter.Unmarshal(raw, &tmplJson)
	if err != nil {
		return nil, fmt.Errorf("error occurs while reading template json, please check whether templateJson variable is correct json format")
	}
	tmplJson.Variant, tmplJson.CoreVersion, _ = where.GetV2rayServiceVersion()
	t = &tmplJson
	t.Setting = setting
	// log
	logLevel := setting.LogLevel
	if logLevel == "" {
		logLevel = conf.GetEnvironmentConfig().LogLevel
	}
	logLevel = strings.ToLower(logLevel)
	t.Log = new(coreObj.Log)
	switch logLevel {
	case "trace", "debug":
		t.Log.Loglevel = "debug"
		t.Log.Access = ""
		t.Log.Error = ""
	case "info":
		t.Log.Loglevel = "info"
		t.Log.Access = ""
		t.Log.Error = "none"
	case "warn", "warning":
		t.Log.Loglevel = "warning"
		t.Log.Access = "none"
		t.Log.Error = ""
	case "error":
		t.Log.Loglevel = "error"
		t.Log.Access = "none"
		t.Log.Error = ""
	default:
		t.Log = nil
	}
	// resolve Outbounds
	supportUDP, outboundTags, err := t.resolveOutbounds(serverData)
	if err != nil {
		return nil, err
	}
	t.OutboundTags = outboundTags

	//set inbound ports according to the setting
	if err = t.setInbound(setting); err != nil {
		return nil, err
	}
	//set DNS
	dnsRouting, err := t.setDNS(serverInfos, supportUDP)
	if err != nil {
		return nil, err
	}
	//append a DNS outbound
	t.appendDNSOutbound()
	//DNS routing
	t.Routing.DomainMatcher = "mph"
	t.setDNSRouting(dnsRouting, supportUDP)
	//rule port routing
	if err = t.setRulePortRouting(); err != nil {
		return nil, err
	}
	//transparent routing
	if IsTransparentOn(setting) {
		if err = t.setTransparentRouting(); err != nil {
			return nil, err
		}
	}
	//set vmess inbound routing
	t.setVmessInboundRouting()
	// set api
	if t.API == nil {
		if _, err = t.SetAPI(serverData); err != nil {
			return nil, err
		}
	}
	// set routing whitelist
	var whitelist []Addr
	for _, info := range serverInfos {
		port := ""
		if info.Info.GetPort() != 0 {
			port = strconv.Itoa(info.Info.GetPort())
		}
		whitelist = append(whitelist, Addr{
			host: info.Info.GetHostname(),
			port: port,
		})
	}
	t.setWhitelistRouting(whitelist)

	t.updatePrivateRouting()

	// add spare tire outbound routing. Fix: https://github.com/v2rayA/v2rayA/issues/447
	t.Routing.Rules = append(t.Routing.Rules, coreObj.RoutingRule{Type: "field", Port: "0-65535", OutboundTag: "proxy"})

	// Set group routing. This should be put in the end of routing setters.
	t.setGroupRouting()

	t.optimizeGeoipMemoryOccupation()

	//set outboundSockopt
	t.SetOutboundSockopt()

	//set fakedns destOverride
	t.setInboundFakeDnsDestOverride()

	//set inbound listening address and routing
	t.setDualStack()

	if IsTransparentOn(t.Setting) {
		switch t.Setting.TransparentType {
		case configure.TransparentGvisorTun, configure.TransparentSystemTun:
			//set outbound sendThrough address
			t.setSendThrough()
		}
	}

	//check if there are any duplicated tags
	if err = t.checkDuplicatedTags(); err != nil {
		return nil, err
	}
	//check if there are any duplicated inbound ports
	if err = t.checkDuplicatedInboundSockets(); err != nil {
		return nil, err
	}

	return t, nil
}

func (t *Template) checkDuplicatedTags() error {
	inboundTagsSet := make(map[string]interface{})
	for _, in := range t.Inbounds {
		tag := in.Tag
		if _, exists := inboundTagsSet[tag]; exists {
			return fmt.Errorf("duplicated inbound tag: %v", tag)
		} else {
			inboundTagsSet[tag] = nil
		}
	}
	outboundTagsSet := make(map[string]interface{})
	for _, out := range t.Outbounds {
		tag := out.Tag
		if _, exists := outboundTagsSet[tag]; exists {
			return fmt.Errorf("duplicated outbound tag: %v", tag)
		} else {
			outboundTagsSet[tag] = nil
		}
	}
	return nil
}

func (t *Template) checkDuplicatedInboundSockets() error {
	inboundSocketSet := make(map[string]interface{})
	for _, in := range t.Inbounds {
		if in.Listen == "" {
			// https://www.v2fly.org/config/inbounds.html#inboundobject
			in.Listen = "0.0.0.0"
		}
		socket := net.JoinHostPort(in.Listen, strconv.Itoa(in.Port))
		if _, exists := inboundSocketSet[socket]; exists {
			return fmt.Errorf("duplicated inbound listening address: %v", socket)
		} else {
			inboundSocketSet[socket] = nil
		}
	}
	return nil
}

var OccupiedErr = fmt.Errorf("port is occupied")

func PortOccupied(syntax []string) (err error) {
	occupied, sockets, err := ports.IsPortOccupied(syntax)
	if err != nil {
		if errors.Is(err, netstat.ErrorNotSupportOSErr) {
			log.Trace("PortOccupied: %v", err)
			return nil
		}
		return
	}
	if occupied {
		if err = netstat.FillProcesses(sockets); err != nil {
			if errors.Is(err, netstat.ErrorNotSupportOSErr) {
				log.Warn("cannot judge port occupation: %v", err)
				return nil
			}
			return fmt.Errorf("failed to check if port is occupied: %w", err)
		}
		for _, s := range sockets {
			p := s.Proc
			if p == nil {
				continue
			}
			if ownPID := strconv.Itoa(os.Getpid()); p.PPID == ownPID ||
				p.PID == ownPID {
				continue
			}
			occupiedErr := fmt.Errorf("%w by %v(%v): %v", OccupiedErr, p.Name, p.PID, s.LocalAddress.Port)
			if configure.GetSettingNotNil().PortSharing {
				// want to listen 0.0.0.0, which conflicts with all IPs
				return occupiedErr
			}
			if s.LocalAddress.IP.IsUnspecified() {
				return occupiedErr
			}
			if s.LocalAddress.IP.IsLoopback() {
				return occupiedErr
			}
		}
	}
	return nil
}

func (t *Template) CheckInboundPortsOccupied() (err error) {
	var st []string
	for _, in := range t.Inbounds {
		switch strings.ToLower(in.Protocol) {
		case "http", "vmess", "vless", "trojan":
			st = append(st, strconv.Itoa(in.Port)+":tcp")
		case "dokodemo-door":
			if strings.HasPrefix(in.Tag, "dns-in") {
				// checked before
				continue
			} else if in.Settings != nil && in.Settings.Network != "" {
				st = append(st, strconv.Itoa(in.Port)+":"+in.Settings.Network)
			} else {
				st = append(st, strconv.Itoa(in.Port)+":tcp,udp")
			}
		default:
			st = append(st, strconv.Itoa(in.Port)+":tcp,udp")
		}
	}
	return PortOccupied(st)
}

func (t *Template) ToConfigBytes() []byte {
	b, _ := jsoniter.Marshal(t)
	return b
}

func WriteV2rayConfig(content []byte) (err error) {
	err = os.WriteFile(asset.GetV2rayConfigPath(), content, os.FileMode(0600))
	if err != nil {
		return fmt.Errorf("WriteV2rayConfig: %w", err)
	}
	return
}

func NewEmptyTemplate(setting *configure.Setting) (t *Template) {
	t = new(Template)
	t.Variant, t.CoreVersion, _ = where.GetV2rayServiceVersion()
	if setting != nil {
		setting.FillEmpty()
	} else {
		setting = configure.GetSettingNotNil()
	}
	t.Setting = setting
	return t
}

func (t *Template) checkAndSetMark(o *coreObj.OutboundObject, mark int) {
	if !IsTransparentOn(t.Setting) {
		return
	}
	if o.StreamSettings == nil {
		o.StreamSettings = new(coreObj.StreamSettings)
	}
	if o.StreamSettings.Sockopt == nil {
		o.StreamSettings.Sockopt = new(coreObj.Sockopt)
	}
	o.StreamSettings.Sockopt.Mark = &mark
}

func (t *Template) InsertMappingOutbound(o serverObj.ServerObj, inboundPort string, udpSupport bool, pluginPort int, protocol string) (err error) {
	if t.CoreVersion == "" {
		t.Variant, t.CoreVersion, _ = where.GetV2rayServiceVersion()
	}
	c, err := o.Configuration(serverObj.PriorInfo{
		Variant:     t.Variant,
		CoreVersion: t.CoreVersion,
		Tag:         "outbound" + inboundPort,
		PluginPort:  pluginPort,
	})
	if err != nil {
		return err
	}
	if len(c.PluginChain) > 0 {
		if server, err := plugin.ServerFromChain(c.PluginChain, o.GetName()); err != nil {
			return err
		} else {
			t.Plugins = append(t.Plugins, server)
		}
	}
	if c.PluginManagerServerLink != "" {
		t.PluginManagerInfoList = append(t.PluginManagerInfoList, PluginManagerInfo{
			Link: c.PluginManagerServerLink,
			Port: pluginPort,
		})
	}
	var mark = 0x80
	t.checkAndSetMark(&c.CoreOutbound, mark)
	t.Outbounds = append(t.Outbounds, c.CoreOutbound)
	t.Outbounds = append(t.Outbounds, c.ExtraOutbounds...)
	iPort, err := strconv.Atoi(inboundPort)
	if err != nil || iPort <= 0 {
		return fmt.Errorf("port of inbound must be a positive number with string type")
	}
	if protocol == "" {
		protocol = "socks"
	}
	t.Inbounds = append(t.Inbounds, coreObj.Inbound{
		Port:     iPort,
		Protocol: protocol,
		Listen:   "0.0.0.0",
		Sniffing: coreObj.Sniffing{
			Enabled:      false,
			DestOverride: []string{"http", "tls"},
		},
		Settings: &coreObj.InboundSettings{
			Auth: "noauth",
			UDP:  udpSupport,
		},
		Tag: "inbound" + inboundPort,
	})
	if t.Routing.DomainStrategy == "" {
		t.Routing.DomainStrategy = "IPOnDemand"
	}
	//插入最前
	tmp := make([]coreObj.RoutingRule, 1, len(t.Routing.Rules)+1)
	tmp[0] = coreObj.RoutingRule{
		Type:        "field",
		OutboundTag: "outbound" + inboundPort,
		InboundTag:  []string{"inbound" + inboundPort},
	}
	t.Routing.Rules = append(tmp, t.Routing.Rules...)
	return
}
