package main

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Второй шаг входа и подключение 2FA. После пароля выдаётся короткая cookie «lp» (10 мин),
// полноценная сессия «ld» — только после кода из приложения.

func (s *srv) setPending(w http.ResponseWriter, r *http.Request, u *user) {
	exp := strconv.FormatInt(time.Now().Add(10*time.Minute).Unix(), 10)
	http.SetCookie(w, &http.Cookie{Name: "lp", Value: u.Name + "." + exp + "." + s.sessionSig(u.Name, exp, u.Hash+"|pending"), Path: "/",
		HttpOnly: true, Secure: isHTTPS(r), SameSite: http.SameSiteLaxMode, MaxAge: 600})
}

func (s *srv) pendingUser(r *http.Request) *user {
	c, err := r.Cookie("lp")
	if err != nil {
		return nil
	}
	p := strings.Split(c.Value, ".")
	if len(p) != 3 {
		return nil
	}
	exp, err := strconv.ParseInt(p[1], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return nil
	}
	u := s.users.get(p[0])
	if u == nil || !hmac.Equal([]byte(p[2]), []byte(s.sessionSig(u.Name, p[1], u.Hash+"|pending"))) {
		return nil
	}
	return u
}

func (s *srv) pending(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := s.pendingUser(r)
		if u == nil {
			http.Error(w, "сессия входа истекла, войдите заново", 401)
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), userKey{}, u)))
	}
}

func (s *srv) finishLogin(w http.ResponseWriter, r *http.Request, name string) {
	http.SetCookie(w, &http.Cookie{Name: "lp", Value: "", Path: "/", MaxAge: -1})
	u := s.users.get(name)
	s.setSession(w, r, u)
	// вход — в колокольчик и push на все устройства пользователя
	ua, ip := r.UserAgent(), clientIP(r)
	go func() { s.alertUser(name, "🔐 Вход в аккаунт: "+who(ua, ip), "/") }()
}

// POST /login/code (форма): код из приложения
func (s *srv) loginCode(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if s.tooMany(ip) {
		http.Redirect(w, r, "/login.html?step=code&e=2", http.StatusSeeOther)
		return
	}
	u := s.pendingUser(r)
	if u == nil {
		http.Redirect(w, r, "/login.html?e=3", http.StatusSeeOther)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	st := totpCheck(u.TOTP, r.FormValue("code"), u.LastOTP)
	if u.TOTP == "" || st == 0 {
		s.fail(ip)
		if u.TOTP != "" { // пароль верный, код — нет: стоит знать владельцу
			ua, nm := r.UserAgent(), u.Name
			go func() {
				s.alertUser(nm, "⚠️ Неверный код 2FA при входе в ваш аккаунт (пароль был введён верно). Если это не вы — смените пароль.\n"+who(ua, ip), "/")
			}()
		}
		time.Sleep(500 * time.Millisecond)
		http.Redirect(w, r, "/login.html?step=code&e=4", http.StatusSeeOther)
		return
	}
	s.users.update(u.Name, func(x *user) { x.LastOTP = st })
	s.finishLogin(w, r, u.Name)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// GET /api/2fa/setup: секрет для подключения (только если 2FA ещё нет)
func (s *srv) totpSetup(w http.ResponseWriter, r *http.Request) {
	u := userOf(r)
	if u.TOTP != "" {
		http.Error(w, "2FA уже подключена", 409)
		return
	}
	sec := u.TOTPNew
	if sec == "" {
		sec = newTOTPSecret()
		s.users.update(u.Name, func(x *user) { x.TOTPNew = sec })
	}
	svg, _ := qrSVG(totpURI(u.Name, sec))
	writeJSON(w, map[string]any{"secret": sec, "uri": totpURI(u.Name, sec), "qr": svg, "name": u.Name})
}

// POST /api/2fa/enable {code}
func (s *srv) totpEnable(w http.ResponseWriter, r *http.Request) {
	var req struct{ Code string }
	json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req)
	u := userOf(r)
	if s.tooMany(clientIP(r)) {
		http.Error(w, "слишком много попыток, подождите 10 минут", 429)
		return
	}
	st := totpCheck(u.TOTPNew, req.Code, 0)
	if u.TOTPNew == "" || st == 0 {
		s.fail(clientIP(r))
		http.Error(w, "неверный код — проверьте время на телефоне и попробуйте ещё раз", 400)
		return
	}
	wasPending := u.Pending
	s.users.update(u.Name, func(x *user) { x.TOTP, x.TOTPNew, x.LastOTP, x.Pending = x.TOTPNew, "", st, false })
	if wasPending {
		msg, ua, ip := "✅ Droply: «"+u.Name+"» завершил регистрацию (2FA подключена)\n", r.UserAgent(), clientIP(r)
		go func() { s.notify(msg + who(ua, ip)) }()
	}
	s.finishLogin(w, r, u.Name)
	w.WriteHeader(204)
}

func (s *srv) reset2FA(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if s.users.update(name, func(x *user) { x.TOTP, x.TOTPNew, x.LastOTP = "", "", 0 }) != nil {
		http.NotFound(w, r)
		return
	}
	w.WriteHeader(204)
}

// ---- регистрация ----

type siteSettings struct {
	mu           sync.Mutex
	path         string
	Registration bool `json:"registration"`
	InviteMode   bool `json:"invite_mode"` // перешли на регистрацию по приглашениям (однократно выключает открытую)
}

func newSiteSettings(dir string) *siteSettings {
	ss := &siteSettings{path: filepath.Join(dir, "site.json")}
	readJSON(ss.path, ss)
	if !ss.InviteMode { // 2026-11: открытая регистрация выключена, вход новых — по приглашениям
		ss.InviteMode, ss.Registration = true, false
		b, _ := json.Marshal(ss)
		os.WriteFile(ss.path, b, 0600)
	}
	return ss
}

func (ss *siteSettings) reg() bool { ss.mu.Lock(); defer ss.mu.Unlock(); return ss.Registration }

func (ss *siteSettings) setReg(v bool) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.Registration = v
	b, _ := json.Marshal(ss)
	os.WriteFile(ss.path, b, 0600)
}

func (s *srv) publicInfo(w http.ResponseWriter, r *http.Request) {
	ok := s.site.reg() || s.invites.valid(r.URL.Query().Get("inv")) != ""
	writeJSON(w, map[string]any{"registration": ok && s.users.count() < s.cfg.MaxUsers})
}

// POST /register (форма): user, password
func (s *srv) register(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	back := func(code string) { http.Redirect(w, r, "/login.html?step=register&e="+code, http.StatusSeeOther) }
	inv := r.FormValue("inv")
	by := s.invites.valid(inv)
	if (!s.site.reg() && by == "") || s.users.count() >= s.cfg.MaxUsers {
		back("5")
		return
	}
	if s.tooMany(ip) || s.regLimited(ip) {
		back("2")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	name := strings.ToLower(strings.TrimSpace(r.FormValue("user")))
	pw := r.FormValue("password")
	if !nameRe.MatchString(name) {
		back("6")
		return
	}
	if weakPw(pw, name) != "" {
		back("7")
		return
	}
	if s.users.get(name) != nil {
		back("8")
		return
	}
	if by != "" && !s.invites.use(inv) { // приглашение одноразовое: второй раз не пустит
		back("5")
		return
	}
	if err := s.users.upsert(name, pw, "", nil, nil); err != nil {
		back("9")
		return
	}
	s.regMu.Lock()
	s.regs[ip] = append(s.regs[ip], time.Now())
	s.regMu.Unlock()
	os.MkdirAll(s.userFiles(name), 0750)
	os.MkdirAll(s.userPart(name), 0750)
	s.users.update(name, func(u *user) { u.Pending = true })
	via := ""
	if by != "" {
		via = " по приглашению от «" + by + "»"
	}
	msg, ua, ip := "🆕 Droply: регистрация «"+name+"»"+via+" (ждёт подключения 2FA)\n", r.UserAgent(), clientIP(r)
	tail := "\nВсего пользователей: " + strconv.Itoa(s.users.count())
	go func() { s.notify(msg + who(ua, ip) + tail) }()
	s.setPending(w, r, s.users.get(name))
	http.Redirect(w, r, "/login.html?step=enroll", http.StatusSeeOther)
}

// не больше 3 регистраций с одного IP в сутки
func (s *srv) regLimited(ip string) bool {
	s.regMu.Lock()
	defer s.regMu.Unlock()
	var recent []time.Time
	for _, t := range s.regs[ip] {
		if time.Since(t) < 24*time.Hour {
			recent = append(recent, t)
		}
	}
	s.regs[ip] = recent
	return len(recent) >= 3
}

func (s *srv) adminSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var req struct{ Registration bool }
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req) == nil {
			s.site.setReg(req.Registration)
		}
	}
	writeJSON(w, map[string]any{"registration": s.site.reg(), "max_users": s.cfg.MaxUsers})
}
