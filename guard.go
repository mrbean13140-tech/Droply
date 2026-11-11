package main

// Защита от перебора: по IP (короткая пауза, бан на час, бан на сутки) и по аккаунту (на случай ботов
// с множеством IP). Баны переживают перезапуск (/data/meta/bans.json).

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

const (
	failShortN, failShortWin = 8, 10 * time.Minute // пауза, пока не схлынет окно
	failHourN, banHour       = 20, time.Hour       // 20 ошибок за час — бан на час
	failDayN, banDay         = 50, 24 * time.Hour  // 50 за сутки — бан на сутки
	acctN, acctWin, acctLock = 10, time.Hour, 15 * time.Minute
)

type guardState struct {
	Bans  map[string]int64 `json:"bans"`  // ip -> до какого времени (unix)
	Locks map[string]int64 `json:"locks"` // логин -> до какого времени
}

var guard = struct {
	st     guardState
	acct   map[string][]time.Time
	loaded bool
}{acct: map[string][]time.Time{}}

func (s *srv) guardPath() string { return filepath.Join(s.cfg.DataDir, "meta", "bans.json") }

// вызывать под s.limMu
func (s *srv) guardLoad() {
	if guard.loaded {
		return
	}
	guard.loaded = true
	readJSON(s.guardPath(), &guard.st)
	if guard.st.Bans == nil {
		guard.st.Bans = map[string]int64{}
	}
	if guard.st.Locks == nil {
		guard.st.Locks = map[string]int64{}
	}
}

func (s *srv) guardSave() {
	now := time.Now().Unix()
	for k, v := range guard.st.Bans {
		if v < now {
			delete(guard.st.Bans, k)
		}
	}
	for k, v := range guard.st.Locks {
		if v < now {
			delete(guard.st.Locks, k)
		}
	}
	b, _ := json.Marshal(guard.st)
	if os.WriteFile(s.guardPath()+".tmp", b, 0600) == nil {
		os.Rename(s.guardPath()+".tmp", s.guardPath())
	}
}

func countSince(ts []time.Time, d time.Duration) int {
	n := 0
	for _, t := range ts {
		if time.Since(t) < d {
			n++
		}
	}
	return n
}

// tooMany — IP сейчас заблокирован (бан или слишком частые ошибки).
func (s *srv) tooMany(ip string) bool {
	s.limMu.Lock()
	defer s.limMu.Unlock()
	s.guardLoad()
	if until := guard.st.Bans[ip]; until > time.Now().Unix() {
		return true
	}
	return countSince(s.failures[ip], failShortWin) >= failShortN
}

// fail — неудачная попытка с IP (пароль, код 2FA, неверная ссылка, пароль ссылки).
func (s *srv) fail(ip string) {
	s.limMu.Lock()
	s.guardLoad()
	ts := append(s.failures[ip], time.Now())
	var keep []time.Time // храним сутки, не больше 200 отметок
	for _, t := range ts {
		if time.Since(t) < banDay {
			keep = append(keep, t)
		}
	}
	if len(keep) > 200 {
		keep = keep[len(keep)-200:]
	}
	s.failures[ip] = keep
	n10, nh, nd := countSince(keep, failShortWin), countSince(keep, time.Hour), len(keep)
	var ban time.Duration
	switch {
	case nd >= failDayN && guard.st.Bans[ip] < time.Now().Add(banHour+time.Minute).Unix():
		ban = banDay
	case nh >= failHourN && guard.st.Bans[ip] < time.Now().Unix():
		ban = banHour
	}
	if ban > 0 {
		guard.st.Bans[ip] = time.Now().Add(ban).Unix()
		s.guardSave()
	}
	alert := n10 == 5 && time.Since(s.alerted[ip]) > time.Hour
	if alert {
		s.alerted[ip] = time.Now()
	}
	s.limMu.Unlock()
	log.Printf("auth: fail ip=%s (10м:%d час:%d сутки:%d)", ip, n10, nh, nd)
	if ban > 0 {
		log.Printf("auth: BAN ip=%s на %s", ip, ban)
		go func() {
			s.notify(fmt.Sprintf("⛔ Droply: IP %s заблокирован на %s — %d неудачных попыток (за час %d)\n📍 %s", ip, banText(ban), nd, nh, place(ip)))
		}()
	} else if alert {
		go func() {
			s.notify("⚠️ Droply: 5 неудачных попыток за 10 минут (пароль, код 2FA или подбор ссылок)\nIP: " + ip + " · " + place(ip) +
				"\nДальше: 8 за 10 мин — пауза, 20 за час — блок на час, 50 за сутки — на сутки.")
		}()
	}
}

func banText(d time.Duration) string {
	if d >= 24*time.Hour {
		return "сутки"
	}
	return "час"
}

// failAcct — неверный пароль к конкретному логину: 10 за час с любых IP — вход в аккаунт закрыт на 15 минут.
func (s *srv) failAcct(name, ip string) {
	if name == "" || s.users.get(name) == nil {
		return
	}
	s.limMu.Lock()
	s.guardLoad()
	var keep []time.Time
	for _, t := range append(guard.acct[name], time.Now()) {
		if time.Since(t) < acctWin {
			keep = append(keep, t)
		}
	}
	guard.acct[name] = keep
	lock := len(keep) >= acctN && guard.st.Locks[name] < time.Now().Unix()
	if lock {
		guard.st.Locks[name] = time.Now().Add(acctLock).Unix()
		guard.acct[name] = nil
		s.guardSave()
	}
	s.limMu.Unlock()
	if lock {
		log.Printf("auth: LOCK user=%s (последний IP %s)", name, ip)
		go s.alertUser(name, fmt.Sprintf("⛔ Droply: %d неверных паролей к вашему аккаунту за час — вход закрыт на 15 минут. Последний IP %s.\nЕсли это не вы — смените пароль.", acctN, ip), "/")
		if u := s.users.get(name); u == nil || !u.Admin {
			go s.notify("⛔ Droply: подбор пароля к аккаунту «" + name + "» — вход закрыт на 15 минут. Последний IP " + ip)
		}
	}
}

func (s *srv) acctLocked(name string) bool {
	s.limMu.Lock()
	defer s.limMu.Unlock()
	s.guardLoad()
	return guard.st.Locks[name] > time.Now().Unix()
}
