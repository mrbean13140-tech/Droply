package main

// Город и провайдер по IP для уведомлений: из локальной базы DB-IP (geodb.go); пока база не скачана —
// запасной вариант ipwho.is (HTTPS, без ключа), ответы кэшируются на сутки.

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

type geoAns struct {
	text string
	t    time.Time
}

var geoCache = struct {
	sync.Mutex
	m map[string]geoAns
}{m: map[string]geoAns{}}

var geoClient = &http.Client{Timeout: 4 * time.Second}

// place — «Москва, Россия · МТС» (пусто, если не удалось)
func place(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	if a.IsPrivate() || a.IsLoopback() {
		return "домашняя сеть"
	}
	if t, ok := localPlace(a); ok { // своя база — никуда не обращаемся
		return t
	}
	geoCache.Lock()
	if v, ok := geoCache.m[ip]; ok && time.Since(v.t) < 24*time.Hour {
		geoCache.Unlock()
		return v.text
	}
	geoCache.Unlock()
	var j struct {
		Success    bool   `json:"success"`
		Country    string `json:"country"`
		Region     string `json:"region"`
		City       string `json:"city"`
		Connection struct {
			ISP string `json:"isp"`
			Org string `json:"org"`
		} `json:"connection"`
	}
	resp, err := geoClient.Get("https://ipwho.is/" + ip + "?lang=ru&fields=success,country,region,city,connection")
	if err != nil {
		return ""
	}
	json.NewDecoder(resp.Body).Decode(&j)
	resp.Body.Close()
	if !j.Success {
		return ""
	}
	var parts []string
	if j.Country == "Российская Федерация" {
		j.Country = "Россия"
	}
	for _, p := range []string{j.City, j.Country} {
		if p != "" && (len(parts) == 0 || parts[len(parts)-1] != p) {
			parts = append(parts, p)
		}
	}
	text := strings.Join(parts, ", ")
	isp := j.Connection.ISP
	if isp == "" {
		isp = j.Connection.Org
	}
	if isp != "" {
		if text != "" {
			text += " · "
		}
		text += isp
	}
	geoCache.Lock()
	if len(geoCache.m) > 2000 {
		geoCache.m = map[string]geoAns{}
	}
	geoCache.m[ip] = geoAns{text, time.Now()}
	geoCache.Unlock()
	return text
}

// who — «iPhone · Safari · IP 1.2.3.4 · Москва, Россия · МТС». Может ждать до 4 с — вызывать в горутине.
func who(ua, ip string) string {
	s := uaShort(ua) + " · IP " + ip
	if p := place(ip); p != "" {
		s += "\n📍 " + p
	}
	return s
}
