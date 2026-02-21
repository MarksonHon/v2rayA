package configure

type (
	AutoUpdateMode          string
	ProxyMode               string
	RulePortMode            string
	PacRuleType             string
	PacMatchType            string
	RoutingDefaultProxyMode string
	TouchType               string
	DefaultYesNo            string
	TransparentMode         string
	TransparentType         string
	InboundSniffing         string
	DnsQueryStrategy        string
)

// DnsServerEntry 表示一条用户自定义的 DNS 服务器规则
type DnsServerEntry struct {
	// Address: DNS 服务器地址，支持 IP、tcp://host:port、https://host/dns-query 等格式
	Address string `json:"address"`
	// Domains: 该服务器负责处理的域名列表，空则表示处理所有其他查询
	Domains []string `json:"domains"`
	// Outbound: DNS 查询走哪个出站，"direct" 或 "proxy"（对应第一个代理 outbound）
	Outbound string `json:"outbound"`
}

const (
	TransparentClose      = TransparentMode("close")
	TransparentProxy      = TransparentMode("proxy") // proxy all traffic
	TransparentWhitelist  = TransparentMode("whitelist")
	TransparentGfwlist    = TransparentMode("gfwlist")
	TransparentFollowRule = TransparentMode("pac")

	TransparentTproxy      = TransparentType("tproxy")
	TransparentRedirect    = TransparentType("redirect")
	TransparentGvisorTun   = TransparentType("gvisor_tun")
	TransparentSystemTun   = TransparentType("system_tun")
	TransparentSystemProxy = TransparentType("system_proxy")

	Default = DefaultYesNo("default")
	Yes     = DefaultYesNo("yes")
	No      = DefaultYesNo("no")

	NotAutoUpdate         = AutoUpdateMode("none")
	AutoUpdate            = AutoUpdateMode("auto_update")
	AutoUpdateAtIntervals = AutoUpdateMode("auto_update_at_intervals")

	ProxyModeDirect = ProxyMode("direct")
	ProxyModePac    = ProxyMode("pac")
	ProxyModeProxy  = ProxyMode("proxy")

	WhitelistMode = RulePortMode("whitelist")
	GfwlistMode   = RulePortMode("gfwlist")
	CustomMode    = RulePortMode("custom")
	RoutingAMode  = RulePortMode("routingA")

	DirectRule = PacRuleType("direct")
	ProxyRule  = PacRuleType("proxy")
	BlockRule  = PacRuleType("block")

	DomainMatchRule = PacMatchType("domain")
	IpMatchRule     = PacMatchType("ip")

	DefaultDirectMode = RoutingDefaultProxyMode("direct")
	DefaultProxyMode  = RoutingDefaultProxyMode("proxy")
	DefaultBlockMode  = RoutingDefaultProxyMode("block")

	SubscriptionType       = TouchType("subscription")
	ServerType             = TouchType("server")
	SubscriptionServerType = TouchType("subscriptionServer")

	InboundSniffingDisable     = InboundSniffing("disable")
	InboundSniffingHttpTLS     = InboundSniffing("http,tls")
	InboundSniffingHttpTlsQuic = InboundSniffing("http,tls,quic")

	// DNS 查询策略（对应 v2ray DnsObject.queryStrategy）
	DnsQueryStrategyUseIP   = DnsQueryStrategy("UseIP")
	DnsQueryStrategyUseIPv4 = DnsQueryStrategy("UseIPv4")
	DnsQueryStrategyUseIPv6 = DnsQueryStrategy("UseIPv6")
)

const (
	RoutingATemplate = `default: proxy
# write your own rules below
domain(domain:mail.qq.com)->direct

domain(geosite:google-scholar)->proxy
domain(geosite:category-scholar-!cn, geosite:category-scholar-cn)->direct
domain(geosite:geolocation-!cn, geosite:google)->proxy
domain(geosite:cn)->direct
ip(geoip:hk,geoip:mo)->proxy
ip(geoip:private, geoip:cn)->direct`
)
