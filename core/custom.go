package core

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/common/file"
	"github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/app/router"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

// hasPublicIPv6 checks if the machine has a public IPv6 address
func hasPublicIPv6() bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP
		if ip.To4() == nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsPrivate() {
			return true
		}
	}
	return false
}

// hasWorkingIPv6 checks if IPv6 connectivity actually works by TCP probing
func hasWorkingIPv6() bool {
	if !hasPublicIPv6() {
		return false
	}
	conn, err := net.DialTimeout("tcp6", "[2001:4860:4860::8888]:53", 3*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func hasOutboundWithTag(list []*core.OutboundHandlerConfig, tag string) bool {
	for _, o := range list {
		if o != nil && o.Tag == tag {
			return true
		}
	}
	return false
}

// loadDnsConfig loads dns.json from configDir if it exists, otherwise returns smart defaults
func loadDnsConfig(configDir string) *coreConf.DNSConfig {
	dnsPath := filepath.Join(configDir, "dns.json")
	if file.IsExist(dnsPath) {
		data, err := os.ReadFile(dnsPath)
		if err != nil {
			log.WithField("err", err).Warn("Failed to read dns.json, using defaults")
		} else {
			dnsConf := &coreConf.DNSConfig{}
			if err := json.Unmarshal(data, dnsConf); err != nil {
				log.WithField("err", err).Warn("Failed to parse dns.json, using defaults")
			} else {
				log.Info("Loaded custom dns.json")
				return dnsConf
			}
		}
	}
	// Default: use public DNS with IPv6 auto-detection
	queryStrategy := "UseIPv4"
	if hasWorkingIPv6() {
		queryStrategy = "UseIPv4v6"
	}
	log.Infof("No dns.json found, using defaults (queryStrategy=%s)", queryStrategy)
	return &coreConf.DNSConfig{
		Servers: []*coreConf.NameServerConfig{
			{
				Address: &coreConf.Address{
					Address: xnet.ParseAddress("8.8.8.8"),
				},
			},
			{
				Address: &coreConf.Address{
					Address: xnet.ParseAddress("1.1.1.1"),
				},
			},
		},
		QueryStrategy: queryStrategy,
	}
}

// loadCustomOutbound loads custom_outbound.json from configDir if it exists
func loadCustomOutbound(configDir string) []*core.OutboundHandlerConfig {
	outPath := filepath.Join(configDir, "custom_outbound.json")
	if !file.IsExist(outPath) {
		return nil
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		log.WithField("err", err).Warn("Failed to read custom_outbound.json")
		return nil
	}
	var outbounds []coreConf.OutboundDetourConfig
	if err := json.Unmarshal(data, &outbounds); err != nil {
		log.WithField("err", err).Warn("Failed to parse custom_outbound.json")
		return nil
	}
	var result []*core.OutboundHandlerConfig
	for i, o := range outbounds {
		built, err := o.Build()
		if err != nil {
			log.WithFields(log.Fields{"err": err, "index": i, "tag": o.Tag}).Warn("Failed to build custom outbound")
			continue
		}
		result = append(result, built)
	}
	log.Infof("Loaded %d custom outbound(s) from custom_outbound.json", len(result))
	return result
}

// loadCustomRoute loads route.json from configDir if it exists
func loadCustomRoute(configDir string) []json.RawMessage {
	routePath := filepath.Join(configDir, "route.json")
	if !file.IsExist(routePath) {
		return nil
	}
	data, err := os.ReadFile(routePath)
	if err != nil {
		log.WithField("err", err).Warn("Failed to read route.json")
		return nil
	}
	var rules []json.RawMessage
	if err := json.Unmarshal(data, &rules); err != nil {
		log.WithField("err", err).Warn("Failed to parse route.json")
		return nil
	}
	log.Infof("Loaded %d custom route rule(s) from route.json", len(rules))
	return rules
}

func GetCustomConfig(configDir string, infos []*panel.NodeInfo) (*dns.Config, []*core.OutboundHandlerConfig, *router.Config, error) {
	// === DNS ===
	coreDnsConfig := loadDnsConfig(configDir)

	// === Outbound ===
	defaultOutbound, _ := buildDefaultOutbound()
	coreOutboundConfig := []*core.OutboundHandlerConfig{defaultOutbound}
	block, _ := buildBlockOutbound()
	coreOutboundConfig = append(coreOutboundConfig, block)
	dnsOut, _ := buildDnsOutbound()
	coreOutboundConfig = append(coreOutboundConfig, dnsOut)

	// Load custom outbounds from file — override Default if tag matches
	if customOutbounds := loadCustomOutbound(configDir); len(customOutbounds) > 0 {
		for _, co := range customOutbounds {
			if co.Tag == "Default" {
				// Replace the default freedom outbound
				coreOutboundConfig[0] = co
			} else if !hasOutboundWithTag(coreOutboundConfig, co.Tag) {
				coreOutboundConfig = append(coreOutboundConfig, co)
			}
		}
	}

	// === Route ===
	domainStrategy := "AsIs"
	dnsRule, _ := json.Marshal(map[string]interface{}{
		"port":        "53",
		"network":     "udp",
		"outboundTag": "dns_out",
	})
	coreRouterConfig := &coreConf.RouterConfig{
		RuleList:       []json.RawMessage{dnsRule},
		DomainStrategy: &domainStrategy,
	}

	// Load custom route rules from file
	if customRules := loadCustomRoute(configDir); len(customRules) > 0 {
		coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, customRules...)
	}

	// === Panel-derived routes (from each node's Routes config) ===
	for _, info := range infos {
		if len(info.Common.Routes) == 0 {
			continue
		}
		for _, route := range info.Common.Routes {
			switch route.Action {
			case "dns":
				if route.ActionValue == nil {
					continue
				}
				server := &coreConf.NameServerConfig{
					Address: &coreConf.Address{
						Address: xnet.ParseAddress(*route.ActionValue),
					},
				}
				if len(route.Match) != 0 {
					server.Domains = route.Match
					server.SkipFallback = true
				}
				coreDnsConfig.Servers = append(coreDnsConfig.Servers, server)
			case "block":
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"domain":      route.Match,
					"outboundTag": "block",
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
			case "block_ip":
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"ip":          route.Match,
					"outboundTag": "block",
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
			case "block_port":
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"port":        strings.Join(route.Match, ","),
					"outboundTag": "block",
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
			case "protocol":
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"protocol":    route.Match,
					"outboundTag": "block",
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
			case "route":
				if route.ActionValue == nil {
					continue
				}
				outbound := &coreConf.OutboundDetourConfig{}
				err := json.Unmarshal([]byte(*route.ActionValue), outbound)
				if err != nil {
					continue
				}
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"domain":      route.Match,
					"outboundTag": outbound.Tag,
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
				if hasOutboundWithTag(coreOutboundConfig, outbound.Tag) {
					continue
				}
				custom_outbound, err := outbound.Build()
				if err != nil {
					continue
				}
				coreOutboundConfig = append(coreOutboundConfig, custom_outbound)
			case "route_ip":
				if route.ActionValue == nil {
					continue
				}
				outbound := &coreConf.OutboundDetourConfig{}
				err := json.Unmarshal([]byte(*route.ActionValue), outbound)
				if err != nil {
					continue
				}
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"ip":          route.Match,
					"outboundTag": outbound.Tag,
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
				if hasOutboundWithTag(coreOutboundConfig, outbound.Tag) {
					continue
				}
				custom_outbound, err := outbound.Build()
				if err != nil {
					continue
				}
				coreOutboundConfig = append(coreOutboundConfig, custom_outbound)
			case "default_out":
				if route.ActionValue == nil {
					continue
				}
				outbound := &coreConf.OutboundDetourConfig{}
				err := json.Unmarshal([]byte(*route.ActionValue), outbound)
				if err != nil {
					continue
				}
				rule := map[string]interface{}{
					"inboundTag":  info.Tag,
					"network":     "tcp,udp",
					"outboundTag": outbound.Tag,
				}
				rawRule, err := json.Marshal(rule)
				if err != nil {
					continue
				}
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
				if hasOutboundWithTag(coreOutboundConfig, outbound.Tag) {
					continue
				}
				custom_outbound, err := outbound.Build()
				if err != nil {
					continue
				}
				coreOutboundConfig = append(coreOutboundConfig, custom_outbound)
			default:
				continue
			}
		}
	}
	DnsConfig, err := coreDnsConfig.Build()
	if err != nil {
		return nil, nil, nil, err
	}
	RouterConfig, err := coreRouterConfig.Build()
	if err != nil {
		return nil, nil, nil, err
	}
	return DnsConfig, coreOutboundConfig, RouterConfig, nil
}
