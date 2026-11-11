package main

import (
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Пользователи: у каждого свой каталог файлов, свои ссылки и своя квота.

type user struct {
	Name      string `json:"name"`
	Email     string `json:"email,omitempty"` // для автовхода через Cloudflare Access
	Salt      string `json:"salt"`
	Hash      string `json:"hash"`
	Admin     bool   `json:"admin,omitempty"`
	QuotaMB   int64  `json:"quota_mb,omitempty"` // 0 = по умолчанию
	Created   int64  `json:"created"`
	Keep      bool   `json:"keep,omitempty"`        // файлы хранятся бессрочно (назначает админ)
	MaxFileMB int64  `json:"max_file_mb,omitempty"` // лимит размера файла; 0 = общий
	WeakPw    bool   `json:"weak_pw,omitempty"`     // пароль не проходит текущие правила — попросить сменить
	Pending   bool   `json:"pending,omitempty"`     // зарегистрировался, но не подключил 2FA
	TOTP      string `json:"totp,omitempty"`        // секрет 2FA (подключена)
	TOTPNew   string `json:"totp_new,omitempty"`    // секрет на этапе подключения
	LastOTP   int64  `json:"last_otp,omitempty"`    // последний принятый шаг (защита от повтора)
}

type userStore struct {
	mu   sync.Mutex
	path string
	m    map[string]*user
}

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,31}$`)

func hashPw(pw string, salt []byte) string {
	k, _ := pbkdf2.Key(sha256.New, pw, salt, 120000, 32)
	return hex.EncodeToString(k)
}

func newUserStore(dir string) *userStore {
	st := &userStore{path: filepath.Join(dir, "users.json"), m: map[string]*user{}}
	var list []*user
	if readJSON(st.path, &list) == nil {
		for _, u := range list {
			st.m[u.Name] = u
		}
	}
	return st
}

func (st *userStore) saveLocked() error {
	list := make([]*user, 0, len(st.m))
	for _, u := range st.m {
		list = append(list, u)
	}
	sort.Slice(list, func(a, b int) bool { return list[a].Name < list[b].Name })
	b, _ := json.MarshalIndent(list, "", " ")
	tmp := st.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, st.path)
}

func (st *userStore) get(name string) *user {
	st.mu.Lock()
	defer st.mu.Unlock()
	if u, ok := st.m[name]; ok {
		c := *u
		return &c
	}
	return nil
}

func (st *userStore) byEmail(email string) *user {
	email = strings.ToLower(strings.TrimSpace(email))
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, u := range st.m {
		if email != "" && strings.ToLower(u.Email) == email {
			c := *u
			return &c
		}
	}
	return nil
}

func (st *userStore) list() []user {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make([]user, 0, len(st.m))
	for _, u := range st.m {
		out = append(out, *u)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out
}

// upsert создаёт или меняет пользователя; пустой пароль — не менять.
func (st *userStore) upsert(name, pw, email string, admin *bool, quotaMB *int64) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	u, ok := st.m[name]
	if !ok {
		u = &user{Name: name, Created: time.Now().Unix()}
	}
	if pw != "" {
		salt := make([]byte, 16)
		rand.Read(salt)
		u.Salt, u.Hash = hex.EncodeToString(salt), hashPw(pw, salt)
	}
	if email != "-" {
		u.Email = strings.TrimSpace(email)
	} else {
		u.Email = ""
	}
	if admin != nil {
		u.Admin = *admin
	}
	if quotaMB != nil {
		u.QuotaMB = *quotaMB
	}
	st.m[name] = u
	return st.saveLocked()
}

func (st *userStore) update(name string, f func(*user)) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	u, ok := st.m[name]
	if !ok {
		return os.ErrNotExist
	}
	f(u)
	return st.saveLocked()
}

func (st *userStore) count() int {
	st.mu.Lock()
	defer st.mu.Unlock()
	return len(st.m)
}

func (st *userStore) remove(name string) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	delete(st.m, name)
	return st.saveLocked()
}

func (st *userStore) check(name, pw string) *user {
	u := st.get(name)
	if u == nil {
		hashPw(pw, []byte("dummy-salt-0000")) // одинаковое время ответа
		return nil
	}
	salt, _ := hex.DecodeString(u.Salt)
	if subtle.ConstantTimeCompare([]byte(hashPw(pw, salt)), []byte(u.Hash)) != 1 {
		return nil
	}
	return u
}

// ---- сессии ----

type userKey struct{}

func (s *srv) loadSecret() {
	p := filepath.Join(s.cfg.DataDir, "meta", "session.key")
	if b, err := os.ReadFile(p); err == nil && len(b) == 32 {
		s.secret = b
		return
	}
	s.secret = make([]byte, 32)
	rand.Read(s.secret)
	os.WriteFile(p, s.secret, 0600)
}

// подпись включает часть хэша пароля: смена пароля завершает старые сессии
func (s *srv) sessionSig(name, exp, hash string) string {
	m := hmac.New(sha256.New, s.secret)
	m.Write([]byte(name + "|" + exp + "|" + hash))
	return hex.EncodeToString(m.Sum(nil))
}

func (s *srv) setSession(w http.ResponseWriter, r *http.Request, u *user) {
	exp := strconv.FormatInt(time.Now().Add(30*24*time.Hour).Unix(), 10)
	http.SetCookie(w, &http.Cookie{Name: "ld", Value: u.Name + "." + exp + "." + s.sessionSig(u.Name, exp, u.Hash), Path: "/", HttpOnly: true,
		Secure: isHTTPS(r), SameSite: http.SameSiteLaxMode, MaxAge: 30 * 24 * 3600})
}

func (s *srv) currentUser(r *http.Request) *user {
	if r.Context().Value(lanKey{}) == nil {
		if email := r.Header.Get("Cf-Access-Authenticated-User-Email"); email != "" {
			if u := s.users.byEmail(email); u != nil {
				return u
			}
		}
	}
	c, err := r.Cookie("ld")
	if err != nil {
		return nil
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 3 {
		return nil
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return nil
	}
	u := s.users.get(parts[0])
	if u == nil || !hmac.Equal([]byte(parts[2]), []byte(s.sessionSig(u.Name, parts[1], u.Hash))) {
		return nil
	}
	return u
}

func userOf(r *http.Request) *user { return r.Context().Value(userKey{}).(*user) }

func (s *srv) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := s.currentUser(r)
		if u == nil {
			http.Error(w, "unauthorized", 401)
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), userKey{}, u)))
	}
}

func (s *srv) adminOnly(h http.HandlerFunc) http.HandlerFunc {
	return s.auth(func(w http.ResponseWriter, r *http.Request) {
		if !userOf(r).Admin || r.Context().Value(lanKey{}) == nil {
			http.Error(w, "администрирование доступно только из домашней сети", 403)
			return
		}
		h(w, r)
	})
}

func (s *srv) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if s.tooMany(ip) {
		http.Redirect(w, r, "/login.html?e=2", http.StatusSeeOther)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	uname := strings.ToLower(strings.TrimSpace(r.FormValue("user")))
	if s.acctLocked(uname) {
		http.Redirect(w, r, "/login.html?e=2", http.StatusSeeOther)
		return
	}
	u := s.users.check(uname, r.FormValue("password"))
	if u == nil {
		s.fail(ip)
		s.failAcct(uname, ip)
		time.Sleep(700 * time.Millisecond)
		http.Redirect(w, r, "/login.html?e=1", http.StatusSeeOther)
		return
	}
	// старые простые пароли: после входа попросим сменить
	if weak := weakPw(r.FormValue("password"), u.Name) != ""; weak != u.WeakPw {
		s.users.update(u.Name, func(x *user) { x.WeakPw = weak })
	}
	s.setPending(w, r, u)
	if u.TOTP != "" {
		http.Redirect(w, r, "/login.html?step=code", http.StatusSeeOther)
	} else {
		http.Redirect(w, r, "/login.html?step=enroll", http.StatusSeeOther)
	}
}

func (s *srv) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "ld", Value: "", Path: "/", MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: "lp", Value: "", Path: "/", MaxAge: -1})
	w.WriteHeader(204)
}

func (s *srv) me(w http.ResponseWriter, r *http.Request) {
	u := userOf(r)
	lan := r.Context().Value(lanKey{}) != nil
	writeJSON(w, map[string]any{"name": u.Name, "admin": u.Admin && lan, "email": u.Email, "totp": u.TOTP != "", "keep": u.Keep, "weak_pw": u.WeakPw})
}

func (s *srv) changePassword(w http.ResponseWriter, r *http.Request) {
	var req struct{ Old, New string }
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req) != nil {
		http.Error(w, "bad request", 400)
		return
	}
	u := userOf(r)
	if msg := weakPw(req.New, u.Name); msg != "" {
		http.Error(w, msg, 400)
		return
	}
	if s.users.check(u.Name, req.Old) == nil {
		s.fail(clientIP(r))
		http.Error(w, "неверный текущий пароль", 403)
		return
	}
	s.users.upsert(u.Name, req.New, u.Email, nil, nil)
	s.users.update(u.Name, func(x *user) { x.WeakPw = false })
	s.setSession(w, r, s.users.get(u.Name))
	w.WriteHeader(204)
}

// ---- администрирование ----

func (s *srv) listUsers(w http.ResponseWriter, r *http.Request) {
	out := []map[string]any{}
	for _, u := range s.users.list() {
		used, _ := dirSize(s.userFiles(u.Name), s.userPart(u.Name))
		out = append(out, map[string]any{"name": u.Name, "email": u.Email, "admin": u.Admin, "used": used, "quota": s.userQuota(&u), "totp": u.TOTP != "", "keep": u.Keep, "pending": u.Pending, "max_file": s.userMaxFile(&u), "max_file_mb": u.MaxFileMB})
	}
	writeJSON(w, out)
}

func (s *srv) saveUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name      string  `json:"name"`
		Password  string  `json:"password"`
		Email     string  `json:"email"`
		Admin     *bool   `json:"admin"`
		Keep      *bool   `json:"keep"`
		QuotaGB   float64 `json:"quota_gb"`
		MaxFileMB *int64  `json:"max_file_mb"` // nil — не менять, 0 — общий лимит
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req) != nil {
		http.Error(w, "bad request", 400)
		return
	}
	req.Name = strings.ToLower(strings.TrimSpace(req.Name))
	if !nameRe.MatchString(req.Name) {
		http.Error(w, "логин: 2–32 символа, латиница, цифры, . _ -", 400)
		return
	}
	exists := s.users.get(req.Name) != nil
	if !exists && req.Password == "" {
		http.Error(w, "нужен пароль", 400)
		return
	}
	if req.Password != "" {
		if msg := weakPw(req.Password, req.Name); msg != "" {
			http.Error(w, msg, 400)
			return
		}
	}
	if req.Email != "" && req.Email != "-" {
		if o := s.users.byEmail(req.Email); o != nil && o.Name != req.Name {
			http.Error(w, "этот e-mail уже у пользователя "+o.Name, 409)
			return
		}
	}
	if req.Name == userOf(r).Name && req.Admin != nil && !*req.Admin {
		http.Error(w, "нельзя снять права администратора с себя", 400)
		return
	}
	var q *int64
	if req.QuotaGB > 0 {
		v := int64(req.QuotaGB * 1024)
		q = &v
	}
	email := req.Email
	if exists && email == "" {
		email = s.users.get(req.Name).Email
	}
	if err := s.users.upsert(req.Name, req.Password, email, req.Admin, q); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if req.Keep != nil {
		s.users.update(req.Name, func(u *user) { u.Keep = *req.Keep })
	}
	if req.MaxFileMB != nil && *req.MaxFileMB >= 0 {
		s.users.update(req.Name, func(u *user) { u.MaxFileMB = *req.MaxFileMB })
	}
	os.MkdirAll(s.userFiles(req.Name), 0750)
	os.MkdirAll(s.userPart(req.Name), 0750)
	w.WriteHeader(204)
}

func (s *srv) deleteUser(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == userOf(r).Name {
		http.Error(w, "нельзя удалить себя", 400)
		return
	}
	if s.users.get(name) == nil || !nameRe.MatchString(name) {
		http.NotFound(w, r)
		return
	}
	s.users.remove(name)
	os.RemoveAll(s.userFiles(name))
	os.RemoveAll(s.userPart(name))
	os.RemoveAll(filepath.Join(s.cfg.DataDir, "meta", "thumbs", name))
	os.RemoveAll(filepath.Join(s.cfg.DataDir, "meta", "clips", name+".json"))
	os.Remove(s.evPath(name))
	pushMu.Lock()
	if m := s.loadSubs(); m[name] != nil {
		delete(m, name)
		s.saveSubs(m)
	}
	pushMu.Unlock()
	s.pruneShares()
	w.WriteHeader(204)
}

// Первичный администратор: страница настройки (root) кладёт bootstrap.json, serve его применяет.
func (s *srv) applyBootstrap() {
	p := filepath.Join(s.cfg.DataDir, "meta", "bootstrap.json")
	var b struct{ Name, Password string }
	if readJSON(p, &b) != nil {
		return
	}
	os.Remove(p)
	b.Name = strings.ToLower(strings.TrimSpace(b.Name))
	if !nameRe.MatchString(b.Name) || len(b.Password) < 8 {
		return
	}
	t := true
	email := ""
	if u := s.users.get(b.Name); u != nil {
		email = u.Email
	}
	s.users.upsert(b.Name, b.Password, email, &t, nil)
	s.users.update(b.Name, func(u *user) { u.TOTP, u.TOTPNew, u.LastOTP = "", "", 0 }) // сброс 2FA
	os.MkdirAll(s.userFiles(b.Name), 0750)
	os.MkdirAll(s.userPart(b.Name), 0750)
}
