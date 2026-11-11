package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Проверка на настоящих базах DB-IP: запускается в CI (DROPLY_GEO_TEST=1), локально пропускается.
func TestGeoDB(t *testing.T) {
	if os.Getenv("DROPLY_GEO_TEST") == "" {
		t.Skip("DROPLY_GEO_TEST не задан")
	}
	dir := t.TempDir()
	for _, p := range []string{"dbip-asn-lite", "dbip-city-lite"} {
		if err := downloadGeo(p, filepath.Join(dir, p+".mmdb")); err != nil {
			t.Fatal(p, err)
		}
	}
	city, err := openMMDB(filepath.Join(dir, "dbip-city-lite.mmdb"))
	if err != nil {
		t.Fatal(err)
	}
	asn, err := openMMDB(filepath.Join(dir, "dbip-asn-lite.mmdb"))
	if err != nil {
		t.Fatal(err)
	}
	geoDB.city, geoDB.asn = city, asn
	for ip, want := range map[string]string{"77.88.8.8": "Россия", "8.8.8.8": "США", "176.59.1.1": "мобильная сеть · Т2", "178.178.232.26": "мобильная сеть · МегаФон", "2a02:6b8::2:242": "Россия"} {
		got, ok := localPlace(netip.MustParseAddr(ip))
		t.Logf("%s -> %q", ip, got)
		if !ok || !strings.Contains(got, want) {
			t.Errorf("%s: %q, want %q", ip, got, want)
		}
	}
	m, _ := city.lookup(netip.MustParseAddr("176.59.1.1"))
	t.Logf("raw: %v", m)
}
