package main

import (
	"encoding/json"
	"time"
)

// Field names follow the mihomo controller REST schema; encoding/json ignores
// unknown keys, so a newer core adds fields without breaking this console.
type Proxy struct {
	Type string   `json:"type"`
	Now  string   `json:"now"`
	All  []string `json:"all"`
}

type ProxiesDoc struct {
	Proxies map[string]Proxy `json:"proxies"`
}

type ConnMeta struct {
	Host        string `json:"host"`
	HostOnly    string `json:"hostOnly"`
	DstIP       string `json:"destinationIP"`
	DstPort     string `json:"destinationPort"`
	Network     string `json:"network"`
	SourceIP    string `json:"sourceIP"`
	SourcePort  string `json:"sourcePort"`
	InboundUser string `json:"inboundUser"`
}

type Conn struct {
	ID          string    `json:"id"`
	Start       time.Time `json:"start"`
	Upload      int64     `json:"upload"`
	Download    int64     `json:"download"`
	Chains      []string  `json:"chains"`
	Rule        string    `json:"rule"`
	RulePayload string    `json:"rulePayload"`
	Metadata    ConnMeta  `json:"metadata"`
}

type ConnectionsDoc struct {
	DownloadTotal int64  `json:"downloadTotal"`
	UploadTotal   int64  `json:"uploadTotal"`
	Connections   []Conn `json:"connections"`
}

type Rule struct {
	Type    string `json:"type"`
	Payload string `json:"payload"`
	Proxy   string `json:"proxy"`
}

type RulesDoc struct {
	Rules []Rule `json:"rules"`
}

type RuleProvider struct {
	Name        string `json:"name"`
	Behavior    string `json:"behavior"`
	RuleCount   int    `json:"ruleCount"`
	UpdatedAt   string `json:"updatedAt"`
	VehicleType string `json:"vehicleType"`
}

type RuleProvidersDoc struct {
	Providers map[string]RuleProvider `json:"providers"`
}

type VersionDoc struct {
	Version string `json:"version"`
	Meta    bool   `json:"meta"`
}

type ConfigsDoc struct {
	Mode      string `json:"mode"`
	Port      int    `json:"port"`
	MixedPort int    `json:"mixed-port"`
	SocksPort int    `json:"socks-port"`
}

type ProxyProvider struct {
	Name        string            `json:"name"`
	VehicleType string            `json:"vehicleType"`
	UpdatedAt   string            `json:"updatedAt"`
	Proxies     []json.RawMessage `json:"proxies"`
}

func (p ProxyProvider) NodeCount() int { return len(p.Proxies) }

type ProxyProvidersDoc struct {
	Providers map[string]ProxyProvider `json:"providers"`
}

type DNSRecord struct {
	Type string `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

type DNSAnswer struct {
	Answer []DNSRecord `json:"Answer"`
}

type MemoryDoc struct {
	Inuse   int64 `json:"inuse"`
	OSLimit int64 `json:"oslimit"`
}

type Traffic struct {
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

type LogLine struct {
	Type    string `json:"type"`
	Payload string `json:"payload"`
}
