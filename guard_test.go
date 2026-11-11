package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGuard(t *testing.T) {
	guard.loaded, guard.st, guard.acct = false, guardState{}, map[string][]time.Time{}
	dir, _ := os.MkdirTemp("", "guard") // не TempDir: уведомления пишутся в фоне и после конца теста
	t.Cleanup(func() { time.Sleep(200 * time.Millisecond); os.RemoveAll(dir) })
	os.MkdirAll(filepath.Join(dir, "meta"), 0750)
	s := &srv{cfg: &Config{DataDir: dir}, failures: map[string][]time.Time{}, alerted: map[string]time.Time{}}
	s.users = newUserStore(filepath.Join(dir, "meta"))
	s.users.upsert("bob", "Kot-na-krishe7", "-", nil, nil)
	ip := "203.0.113.5"
	// медленный бот: 1 попытка в 4 минуты — короткое окно не срабатывает, а часовое — да
	for i := 0; i < 19; i++ {
		s.failures[ip] = append(s.failures[ip], time.Now().Add(-time.Duration(i*3)*time.Minute))
	}
	if s.tooMany(ip) {
		t.Fatal("рано заблокировал")
	}
	s.fail(ip)
	if !s.tooMany(ip) || guard.st.Bans[ip] == 0 {
		t.Fatal("нет бана на час после 20 ошибок за час")
	}
	// бан переживает перезапуск
	guard.loaded, guard.st = false, guardState{}
	s2 := &srv{cfg: s.cfg, failures: map[string][]time.Time{}, alerted: map[string]time.Time{}}
	if !s2.tooMany(ip) {
		t.Fatal("бан не сохранился")
	}
	// перебор аккаунта с разных IP
	for i := 0; i < acctN; i++ {
		s.failAcct("bob", "198.51.100."+string(rune('0'+i)))
	}
	if !s.acctLocked("bob") {
		t.Fatal("аккаунт не закрыт")
	}
	if s.acctLocked("nobody") {
		t.Fatal("лишняя блокировка")
	}
}
