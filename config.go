package main

import (
	"encoding/json"
	"os"
	"strings"
)

type Config struct {
	IP             string   `json:"ip"`           // 10.101.101.50/24
	GW             string   `json:"gw"`           // 10.101.101.1
	DNS            []string `json:"dns"`          // ["1.1.1.1"]
	Iface          string   `json:"iface"`        // eth0
	TunnelToken    string   `json:"tunnel_token"` // cloudflared token
	Emails         []string `json:"emails"`       // доп. allowlist поверх CF Access (пусто = доверять CF)
	Password       string   `json:"password"`     // вход паролем (режим без CF, напр. KeenDNS)
	Listen         string   `json:"listen"`       // 127.0.0.1:8080
	SetupListen    string   `json:"setup_listen"` // :8081 страница настройки
	LanListen      string   `json:"lan_listen"`   // вход из локалки по паролю (по умолчанию <IP>:8080)
	DataDir        string   `json:"data_dir"`     // /data
	MaxFileGB      float64  `json:"max_file_gb"`
	MaxFileMB      int64    `json:"max_file_mb"`   // приоритетнее max_file_gb
	QuotaGB        float64  `json:"quota_gb"`      // общая
	UserQuotaGB    float64  `json:"user_quota_gb"` // на пользователя по умолчанию
	TTLDays        int      `json:"ttl_days"`
	MaxUsers       int      `json:"max_users"`
	AllowCountries []string `json:"allow_countries"` // пусто = без фильтра
	AllowHosts     []string `json:"allow_hosts"`     // хосты/IP, которым можно из любой страны
	TGToken        string   `json:"tg_token"`        // не используется (Telegram отключён 2026-11-11)
	TLSListen      string   `json:"tls_listen"`      // прямой HTTPS (сертификат Let's Encrypt), напр. :8443
	TLSDomain      string   `json:"tls_domain"`
	ProxyIPs       []string `json:"proxy_ips"` // обратные прокси (KeenDNS роутера): их запросы считаются внешними
	TGChat         string   `json:"tg_chat"`
}

const configPath = "/etc/landrop.json"

func loadConfig() (*Config, error) {
	c := &Config{Iface: "eth0", Listen: "127.0.0.1:8080", DataDir: "/data", MaxFileGB: 20, MaxFileMB: 76, QuotaGB: 18, UserQuotaGB: 1, TTLDays: 7, MaxUsers: 20}
	if p := os.Getenv("LANDROP_CONFIG"); p != "" {
		return c, readJSON(p, c)
	}
	return c, readJSON(configPath, c)
}

func readJSON(p string, v any) error {
	b, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// LanAddr — адрес для входа из локальной сети (только при заданном пароле).
func (c *Config) LanAddr() string {
	if c.LanListen != "" {
		return c.LanListen
	}
	if c.IP == "" {
		return ""
	}
	return strings.Split(c.IP, "/")[0] + ":8080"
}
