package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Доступ через туннель: только из разрешённых стран (заголовок CF-IPCountry от Cloudflare)
// или с адресов разрешённых хостов (VPN-серверы; IP берутся из DNS и обновляются сами).

type geoGuard struct {
	countries map[string]bool
	hosts     []string
	mu        sync.RWMutex
	ips       map[string]bool
	nets      []netip.Prefix // разрешённые подсети из allow_hosts (CIDR)
	v4        [][2]uint32    // диапазоны IPv4 разрешённых стран (из RIPE), отсортированы
	v6        []netip.Prefix // префиксы IPv6
	cache     string
	allowFile string // /data/meta/allow.txt — VPN-серверы и прочие разрешённые адреса (не в публичном репозитории)
}

// allowList — адреса из конфига + из allow.txt (по одному в строке, # — комментарий).
func (g *geoGuard) allowList() []string {
	out := append([]string(nil), g.hosts...)
	b, err := os.ReadFile(g.allowFile)
	if err != nil {
		return out
	}
	for _, l := range strings.Split(string(b), "\n") {
		if i := strings.Index(l, "#"); i >= 0 {
			l = l[:i]
		}
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func newGeoGuard(cfg *Config) *geoGuard {
	g := &geoGuard{countries: map[string]bool{}, hosts: cfg.AllowHosts, ips: map[string]bool{},
		cache:     filepath.Join(cfg.DataDir, "meta", "ripe-delegated.txt"),
		allowFile: filepath.Join(cfg.DataDir, "meta", "allow.txt")}
	// перенос: адреса из старого конфига образа -> allow.txt на диске данных (однократно)
	if _, err := os.Stat(g.allowFile); os.IsNotExist(err) && len(cfg.AllowHosts) > 0 {
		os.WriteFile(g.allowFile, []byte("# разрешённые адреса (VPN-серверы): домен, IP или подсеть — по одному в строке\n"+strings.Join(cfg.AllowHosts, "\n")+"\n"), 0640)
		log.Printf("geo: allow-list перенесён в %s (%d адресов)", g.allowFile, len(cfg.AllowHosts))
	}
	for _, c := range cfg.AllowCountries {
		g.countries[strings.ToUpper(c)] = true
	}
	if len(g.countries) > 0 {
		go g.refreshLoop()
		go g.ripeLoop()
	}
	return g
}

func (g *geoGuard) refreshLoop() {
	for {
		ips := map[string]bool{}
		var nets []netip.Prefix
		for _, h := range g.allowList() {
			h = strings.TrimSpace(h)
			if pf, err := netip.ParsePrefix(h); err == nil {
				nets = append(nets, pf)
				continue
			}
			if ip := net.ParseIP(h); ip != nil {
				ips[ip.String()] = true
				continue
			}
			addrs, err := net.LookupHost(h)
			if err != nil {
				log.Printf("geo: %s: %v", h, err)
				continue
			}
			for _, a := range addrs {
				ips[net.ParseIP(a).String()] = true
			}
		}
		g.mu.Lock()
		if len(ips) > 0 {
			g.ips = ips
		}
		g.nets = nets
		g.mu.Unlock()
		time.Sleep(10 * time.Minute)
	}
}

func (g *geoGuard) allowed(r *http.Request) bool {
	if len(g.countries) == 0 || r.Context().Value(lanKey{}) != nil {
		return true // фильтр выключен или запрос из локальной сети
	}
	cc := strings.ToUpper(r.Header.Get("Cf-Ipcountry"))
	if cc != "" && g.countries[cc] {
		return true // страну сообщил Cloudflare
	}
	ipStr := r.Header.Get("Cf-Connecting-Ip")
	if ipStr == "" {
		ipStr, _, _ = net.SplitHostPort(r.RemoteAddr)
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsPrivate() || ip.IsLoopback() {
		return true // из домашней сети по доменному имени (через роутер)
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.ips[ip.String()] {
		return true
	}
	if a, ok := netip.AddrFromSlice(ip); ok {
		a = a.Unmap()
		for _, pf := range g.nets {
			if pf.Contains(a) {
				return true
			}
		}
	}
	if cc != "" {
		return false
	}
	// без Cloudflare: страна по спискам RIPE
	if len(g.v4) == 0 && len(g.v6) == 0 {
		return true // список ещё не загружен — не блокируем вслепую
	}
	return g.inRanges(ip)
}

func (g *geoGuard) wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !g.allowed(r) {
			log.Printf("geo: blocked %s %s (%s) %s", r.Header.Get("Cf-Connecting-Ip"), r.RemoteAddr, r.Header.Get("Cf-Ipcountry"), r.URL.Path)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(403)
			w.Write([]byte(publicPage("Доступ ограничен", "<p class='muted'>Сервис недоступен из вашего региона.</p>")))
			return
		}
		h.ServeHTTP(w, r)
	})
}

func (g *geoGuard) inRanges(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		x := binary.BigEndian.Uint32(v4)
		i := sort.Search(len(g.v4), func(i int) bool { return g.v4[i][1] >= x })
		return i < len(g.v4) && g.v4[i][0] <= x
	}
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	for _, p := range g.v6 {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

const ripeURL = "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest"

// Списки адресов стран из статистики RIPE: загрузка раз в сутки, копия на диске.
func (g *geoGuard) ripeLoop() {
	if b, err := os.ReadFile(g.cache); err == nil {
		g.parseRIPE(string(b))
	}
	for {
		st, err := os.Stat(g.cache)
		if err != nil || time.Since(st.ModTime()) > 24*time.Hour {
			if body, err := fetchText(ripeURL); err != nil {
				log.Printf("geo: ripe: %v", err)
			} else if g.parseRIPE(body) {
				os.WriteFile(g.cache+".tmp", []byte(body), 0640)
				os.Rename(g.cache+".tmp", g.cache)
			}
		}
		time.Sleep(time.Hour)
	}
}

func fetchText(u string) (string, error) {
	cl := &http.Client{Timeout: 3 * time.Minute}
	resp, err := cl.Get(u)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("http %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	return string(b), err
}

func (g *geoGuard) parseRIPE(body string) bool {
	var v4 [][2]uint32
	var v6 []netip.Prefix
	for _, line := range strings.Split(body, "\n") {
		f := strings.Split(line, "|")
		if len(f) < 7 || !g.countries[f[1]] || (f[6] != "allocated" && f[6] != "assigned") {
			continue
		}
		switch f[2] {
		case "ipv4":
			ip := net.ParseIP(f[3]).To4()
			n, err := strconv.ParseUint(f[4], 10, 32)
			if ip == nil || err != nil || n == 0 {
				continue
			}
			st := binary.BigEndian.Uint32(ip)
			v4 = append(v4, [2]uint32{st, st + uint32(n) - 1})
		case "ipv6":
			if p, err := netip.ParsePrefix(f[3] + "/" + f[4]); err == nil {
				v6 = append(v6, p)
			}
		}
	}
	if len(v4) < 100 {
		return false // подозрительно мало — не применяем
	}
	sort.Slice(v4, func(a, b int) bool { return v4[a][0] < v4[b][0] })
	// слить пересекающиеся
	m := v4[:1]
	for _, r := range v4[1:] {
		last := &m[len(m)-1]
		if r[0] <= last[1]+1 {
			if r[1] > last[1] {
				last[1] = r[1]
			}
		} else {
			m = append(m, r)
		}
	}
	g.mu.Lock()
	g.v4, g.v6 = m, v6
	g.mu.Unlock()
	log.Printf("geo: ripe loaded %d v4 ranges, %d v6 prefixes", len(m), len(v6))
	return true
}
