package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed web
var webFS embed.FS

type srv struct {
	cfg      *Config
	files    string // корень: files/<user>/
	part     string // корень: part/<user>/
	maxFile  int64
	quota    int64 // общая квота
	uquota   int64 // квота пользователя по умолчанию
	users    *userStore
	secret   []byte
	mu       sync.Mutex // финализация/квота
	upMu     sync.Map   // id -> *sync.Mutex
	limMu    sync.Mutex
	failures map[string][]time.Time
	alerted  map[string]time.Time // тревога о переборе (push) — не чаще раза в час на IP
	invites  *inviteStore
	vk       *vapidKeys
	regMu    sync.Mutex
	regs     map[string][]time.Time
	site     *siteSettings
	sh       *shareStore
}

type partMeta struct {
	Name string `json:"name"`
	Dir  string `json:"dir,omitempty"`
	Size int64  `json:"size"`
}

func serve(cfg *Config) {
	s := &srv{cfg: cfg, files: filepath.Join(cfg.DataDir, "files"), part: filepath.Join(cfg.DataDir, "part"),
		maxFile: int64(cfg.MaxFileGB * (1 << 30)), quota: int64(cfg.QuotaGB * (1 << 30)), failures: map[string][]time.Time{}, regs: map[string][]time.Time{}, alerted: map[string]time.Time{}}
	if cfg.MaxFileMB > 0 {
		s.maxFile = cfg.MaxFileMB << 20
	}
	s.uquota = int64(cfg.UserQuotaGB * (1 << 30))
	os.MkdirAll(s.files, 0750)
	os.MkdirAll(s.part, 0750)
	os.MkdirAll(filepath.Join(cfg.DataDir, "meta"), 0750)
	s.loadSecret()
	s.users = newUserStore(filepath.Join(cfg.DataDir, "meta"))
	s.applyBootstrap()
	s.site = newSiteSettings(filepath.Join(cfg.DataDir, "meta"))
	s.sh = newShareStore(filepath.Join(cfg.DataDir, "meta"))
	s.invites = newInviteStore(filepath.Join(cfg.DataDir, "meta"))
	go s.janitor()
	go s.geoUpdater()

	sub, _ := fs.Sub(webFS, "web")
	static := http.FileServer(http.FS(sub))
	mux := http.NewServeMux()
	mux.HandleFunc("GET /robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("User-agent: *\nDisallow: /\n"))
	})
	mux.HandleFunc("GET /api/files", s.auth(s.listFiles))
	mux.HandleFunc("DELETE /api/files/{name}", s.auth(s.csrf(s.deleteFile)))
	mux.HandleFunc("POST /api/folders", s.auth(s.csrf(s.createFolder)))
	mux.HandleFunc("POST /api/up", s.auth(s.csrf(s.upInit)))
	mux.HandleFunc("PUT /api/up/{id}", s.auth(s.csrf(s.upChunk)))
	mux.HandleFunc("DELETE /api/up/{id}", s.auth(s.csrf(s.upCancel)))
	mux.HandleFunc("GET /api/invite", s.auth(s.invite))
	mux.HandleFunc("GET /api/thumb", s.auth(s.thumb))
	mux.HandleFunc("POST /api/files/rename", s.auth(s.csrf(s.renameFile)))
	mux.HandleFunc("POST /api/files/move", s.auth(s.csrf(s.moveFiles)))
	mux.HandleFunc("GET /api/tree", s.auth(s.folderTree))
	mux.HandleFunc("GET /api/push/key", s.auth(s.pushKey))
	mux.HandleFunc("POST /api/push/sub", s.auth(s.csrf(s.pushSubscribe)))
	mux.HandleFunc("DELETE /api/push/sub", s.auth(s.csrf(s.pushUnsubscribe)))
	mux.HandleFunc("GET /api/events", s.auth(s.listEvents))
	mux.HandleFunc("POST /api/events/seen", s.auth(s.csrf(s.seenEvents)))
	mux.HandleFunc("DELETE /api/events", s.auth(s.csrf(s.clearEvents)))
	mux.HandleFunc("POST /s/{token}/auth", s.shareAuth)
	mux.HandleFunc("POST /s/{token}/up", s.csrf(s.inboxInit))
	mux.HandleFunc("PUT /s/{token}/up/{id}", s.csrf(s.inboxChunk))
	mux.HandleFunc("GET /f/{name}", s.auth(s.download))
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("POST /api/logout", s.csrf(s.logout))
	mux.HandleFunc("POST /login/code", s.loginCode)
	mux.HandleFunc("POST /register", s.register)
	mux.HandleFunc("GET /api/public", s.publicInfo)
	mux.HandleFunc("GET /api/2fa/setup", s.pending(s.totpSetup))
	mux.HandleFunc("POST /api/2fa/enable", s.pending(s.csrf(s.totpEnable)))
	mux.HandleFunc("POST /api/users/{name}/reset2fa", s.adminOnly(s.csrf(s.reset2FA)))
	mux.HandleFunc("GET /api/settings", s.adminOnly(s.adminSettings))
	mux.HandleFunc("POST /api/settings", s.adminOnly(s.csrf(s.adminSettings)))
	mux.HandleFunc("GET /api/me", s.auth(s.me))
	mux.HandleFunc("POST /api/me/password", s.auth(s.csrf(s.changePassword)))
	mux.HandleFunc("GET /api/users", s.adminOnly(s.listUsers))
	mux.HandleFunc("POST /api/users", s.adminOnly(s.csrf(s.saveUser)))
	mux.HandleFunc("DELETE /api/users/{name}", s.adminOnly(s.csrf(s.deleteUser)))
	mux.HandleFunc("GET /api/shares", s.auth(s.listShares))
	mux.HandleFunc("POST /api/shares", s.auth(s.csrf(s.createShare)))
	mux.HandleFunc("DELETE /api/shares/{token}", s.auth(s.csrf(s.deleteShare)))
	mux.HandleFunc("GET /api/shares/{token}/qr.svg", s.auth(s.shareQR))
	mux.HandleFunc("GET /s/{token}", s.publicShare) // публично: только по токену
	mux.HandleFunc("GET /s/{token}/dl", s.publicDownload)
	mux.HandleFunc("GET /s/{token}/zip", s.publicZip)
	for _, n := range []string{"180", "192", "512"} {
		mux.HandleFunc("GET /icon-"+n+".png", iconHandler(n))
	}
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if p == "/login.html" || p == "/style.css" || p == "/login.js" || p == "/manifest.webmanifest" || p == "/upload.js" || p == "/sw.js" {
			static.ServeHTTP(w, r)
			return
		}
		if s.currentUser(r) == nil {
			http.Redirect(w, r, "/login.html", http.StatusFound)
			return
		}
		static.ServeHTTP(w, r)
	})
	geo := newGeoGuard(cfg)
	h := &http.Server{Addr: cfg.Listen, Handler: secHeaders(geo.wrap(mux)), ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout: 120 * time.Second, MaxHeaderBytes: 32 << 10}
	if cfg.LanAddr() != "" {
		lan := &http.Server{Addr: cfg.LanAddr(), ReadHeaderTimeout: 15 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 32 << 10,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// из локалки заголовкам Cloudflare не доверяем — только пароль
				r.Header.Del("Cf-Access-Authenticated-User-Email")
				r.Header.Del("Cf-Connecting-Ip")
				r.Header.Del("Cf-Ipcountry")
				r.Header.Del("Cf-Visitor")
				host, _, _ := net.SplitHostPort(r.RemoteAddr)
				for _, p := range cfg.ProxyIPs {
					if host == p {
						// запрос пришёл через KeenDNS роутера — это интернет, а не домашняя сеть
						ip := strings.TrimSpace(r.Header.Get("X-Real-Ip"))
						if ip == "" {
							f := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
							ip = strings.TrimSpace(f[len(f)-1])
						}
						if net.ParseIP(ip) != nil {
							r.RemoteAddr = net.JoinHostPort(ip, "0")
						}
						h.Handler.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), proxKey{}, true)))
						return
					}
				}
				h.Handler.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), lanKey{}, true)))
			})}
		go func() { log.Printf("lan on %s", cfg.LanAddr()); log.Fatal(lan.ListenAndServe()) }()
	}
	if cfg.TLSDomain != "" && cfg.TLSListen != "" {
		acm := newACME(cfg.TLSDomain, cfg.DataDir)
		hs := &http.Server{Addr: cfg.TLSListen, ReadHeaderTimeout: 15 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 32 << 10,
			TLSConfig: &tls.Config{GetCertificate: acm.getCertificate, MinVersion: tls.VersionTLS12,
				NextProtos: []string{"h2", "http/1.1", "acme-tls/1"}},
			ErrorLog: log.New(io.Discard, "", 0), // сканеры с битым TLS не засоряют журнал
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// прямой вход из интернета: заголовкам Cloudflare не доверяем
				for _, k := range []string{"Cf-Access-Authenticated-User-Email", "Cf-Connecting-Ip", "Cf-Ipcountry", "Cf-Visitor", "X-Real-Ip", "X-Forwarded-For"} {
					r.Header.Del(k)
				}
				if host, _, err := net.SplitHostPort(r.Host); (err == nil && host != cfg.TLSDomain) || (err != nil && r.Host != cfg.TLSDomain) {
					http.Error(w, "not found", 404)
					return
				}
				h.Handler.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), proxKey{}, true)))
			})}
		go func() {
			log.Printf("https on %s for %s", cfg.TLSListen, cfg.TLSDomain)
			log.Fatal(hs.ListenAndServeTLS("", ""))
		}()
	}
	log.Printf("serve on %s", cfg.Listen)
	log.Fatal(h.ListenAndServe())
}

func secHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data: blob:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("X-Robots-Tag", "noindex, nofollow, noarchive") // ссылки не попадают в поисковики
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Cache-Control", "no-store")
		if isHTTPS(r) {
			hd.Set("Strict-Transport-Security", "max-age=31536000")
		}
		h.ServeHTTP(w, r)
	})
}

// ---- auth ----

func clientIP(r *http.Request) string {
	if ip := r.Header.Get("Cf-Connecting-Ip"); ip != "" {
		return ip
	}
	h, _, _ := net.SplitHostPort(r.RemoteAddr)
	return h
}

type lanKey struct{}

// Свой заголовок нельзя отправить с чужого сайта без CORS-preflight -> защита от CSRF.
func (s *srv) csrf(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Landrop") != "1" {
			http.Error(w, "bad request", 400)
			return
		}
		h(w, r)
	}
}

// ---- files ----

var badChars = strings.NewReplacer("/", "_", "\\", "_", ":", "_", "*", "_", "?", "_", "\"", "_", "<", "_", ">", "_", "|", "_")

func cleanName(n string) string {
	n = badChars.Replace(n)
	n = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, n)
	n = strings.Trim(n, " .")
	for len(n) > 180 {
		n = n[:len(n)-1]
	}
	n = strings.ToValidUTF8(n, "")
	if n == "" {
		n = "file"
	}
	return n
}

func (s *srv) userFiles(name string) string { return filepath.Join(s.files, name) }
func (s *srv) userPart(name string) string  { return filepath.Join(s.part, name) }
func (s *srv) userMaxFile(u *user) int64 {
	if u.MaxFileMB > 0 {
		return u.MaxFileMB << 20
	}
	return s.maxFile
}
func (s *srv) userQuota(u *user) int64 {
	if u.QuotaMB > 0 {
		return u.QuotaMB << 20
	}
	return s.uquota
}

// cleanRel проверяет относительный путь внутри хранилища пользователя ("папка/файл").
func cleanRel(rel string) (string, bool) {
	rel = strings.Trim(rel, "/")
	if rel == "" {
		return "", true
	}
	parts := strings.Split(rel, "/")
	if len(parts) > 10 {
		return "", false
	}
	for _, p := range parts {
		if p == "" || p != cleanName(p) || strings.HasPrefix(p, ".") {
			return "", false
		}
	}
	return strings.Join(parts, "/"), true
}

// filePath: путь к файлу или папке пользователя; пустой rel не допускается.
func (s *srv) filePath(owner, rel string) (string, bool) {
	r, ok := cleanRel(rel)
	if !nameRe.MatchString(owner) || !ok || r == "" {
		return "", false
	}
	return filepath.Join(s.files, owner, filepath.FromSlash(r)), true
}

// dirPath: папка пользователя (пустой rel = корень).
func (s *srv) dirPath(owner, rel string) (string, string, bool) {
	r, ok := cleanRel(rel)
	if !nameRe.MatchString(owner) || !ok {
		return "", "", false
	}
	return filepath.Join(s.files, owner, filepath.FromSlash(r)), r, true
}

func joinRel(dir, name string) string {
	if dir == "" {
		return name
	}
	return dir + "/" + name
}

type fileInfo struct {
	Name  string `json:"name"`
	Size  int64  `json:"size"`
	MTime int64  `json:"mtime"`
	Dir   bool   `json:"dir,omitempty"`
	Count int    `json:"count,omitempty"` // файлов в папке
}

// GET /api/files?dir=папка
func (s *srv) listFiles(w http.ResponseWriter, r *http.Request) {
	u := userOf(r)
	os.MkdirAll(s.userFiles(u.Name), 0750)
	d, rel, ok := s.dirPath(u.Name, r.URL.Query().Get("dir"))
	if !ok {
		http.Error(w, "bad path", 400)
		return
	}
	ents, err := os.ReadDir(d)
	if err != nil && rel != "" {
		http.Error(w, "папка не найдена", 404)
		return
	}
	out := []fileInfo{}
	for _, e := range ents {
		i, err := e.Info()
		if err != nil {
			continue
		}
		if e.IsDir() {
			n, cnt := treeSize(filepath.Join(d, e.Name()))
			out = append(out, fileInfo{e.Name(), n, i.ModTime().Unix(), true, cnt})
		} else if i.Mode().IsRegular() {
			out = append(out, fileInfo{e.Name(), i.Size(), i.ModTime().Unix(), false, 0})
		}
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].Dir != out[b].Dir {
			return out[a].Dir
		}
		if out[a].Dir {
			return strings.ToLower(out[a].Name) < strings.ToLower(out[b].Name)
		}
		return out[a].MTime > out[b].MTime
	})
	used, _ := dirSize(s.userFiles(u.Name), s.userPart(u.Name))
	writeJSON(w, map[string]any{"dir": rel, "files": out, "used": used, "quota": s.userQuota(u), "max_file": s.userMaxFile(u), "ttl_days": s.cfg.TTLDays, "keep": u.Keep})
}

// POST /api/folders {dir, name}
func (s *srv) createFolder(w http.ResponseWriter, r *http.Request) {
	var req struct{ Dir, Name string }
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req) != nil {
		http.Error(w, "bad request", 400)
		return
	}
	name := cleanName(req.Name)
	p, ok := s.filePath(userOf(r).Name, joinRel(strings.Trim(req.Dir, "/"), name))
	if !ok || strings.Count(joinRel(req.Dir, name), "/") >= 10 {
		http.Error(w, "недопустимое имя папки", 400)
		return
	}
	if _, err := os.Stat(p); err == nil {
		http.Error(w, "такое имя уже есть", 409)
		return
	}
	if err := os.MkdirAll(p, 0750); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, map[string]string{"name": name})
}

// DELETE /api/files/{name}?dir=  — файл или папка целиком
func (s *srv) deleteFile(w http.ResponseWriter, r *http.Request) {
	p, ok := s.filePath(userOf(r).Name, joinRel(strings.Trim(r.URL.Query().Get("dir"), "/"), r.PathValue("name")))
	if !ok {
		http.Error(w, "not found", 404)
		return
	}
	st, err := os.Stat(p)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	if st.IsDir() {
		err = os.RemoveAll(p)
	} else {
		err = os.Remove(p)
	}
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.WriteHeader(204)
}

func (s *srv) download(w http.ResponseWriter, r *http.Request) {
	s.serveFile(w, r, userOf(r).Name, joinRel(strings.Trim(r.URL.Query().Get("dir"), "/"), r.PathValue("name")))
}

// размер и число файлов в дереве
func treeSize(root string) (int64, int) {
	var n int64
	var c int
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if i, e := d.Info(); e == nil {
				n += i.Size()
				c++
			}
		}
		return nil
	})
	return n, c
}

func (s *srv) serveFile(w http.ResponseWriter, r *http.Request, owner, fname string) {
	p, ok := s.filePath(owner, fname)
	if !ok {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(p)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	name := filepath.Base(p)
	if ct := inlineType(name); ct != "" && r.URL.Query().Get("inline") == "1" && r.Context().Value(userKey{}) != nil {
		// просмотр в приложении: только безопасные типы (без html/svg) и только владельцу
		w.Header().Set("Content-Type", ct)
		w.Header().Set("Content-Disposition", "inline; filename*=UTF-8''"+url.PathEscape(name))
		w.Header().Set("Cache-Control", "private, max-age=600")
		http.ServeContent(w, r, "", st.ModTime(), f)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename*=UTF-8''"+url.PathEscape(name))
	http.ServeContent(w, r, "", st.ModTime(), f)
}

// размер файлов в каталогах (рекурсивно)
func dirSize(dirs ...string) (int64, error) {
	var total int64
	for _, d := range dirs {
		n, _ := treeSize(d)
		total += n
	}
	return total, nil
}

// POST /api/up {name,size} -> {id, offset}. id детерминирован -> докачка после обрыва.
func (s *srv) upInit(w http.ResponseWriter, r *http.Request) {
	var m partMeta
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&m); err != nil || m.Size < 0 {
		http.Error(w, "bad request", 400)
		return
	}
	s.upInitFor(w, r, userOf(r), m, nil)
}

// upInitFor — начало загрузки в хранилище пользователя u. isNew вызывается для новой (не докачка) загрузки;
// вернёт текст ошибки — загрузка отклоняется.
func (s *srv) upInitFor(w http.ResponseWriter, r *http.Request, u *user, m partMeta, isNew func() string) {
	m.Name = cleanName(m.Name)
	dr, ok := cleanRel(m.Dir)
	if !ok {
		http.Error(w, "bad path", 400)
		return
	}
	m.Dir = dr
	if mf := s.userMaxFile(u); m.Size > mf {
		http.Error(w, fmt.Sprintf("файл больше лимита %d МБ", mf>>20), 413)
		return
	}
	if d, _, _ := s.dirPath(u.Name, m.Dir); m.Dir != "" {
		if st, err := os.Stat(d); err != nil || !st.IsDir() {
			http.Error(w, "папка не найдена", 404)
			return
		}
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d", m.Dir, m.Name, m.Size)))
	id := hex.EncodeToString(sum[:12])
	os.MkdirAll(s.userPart(u.Name), 0750)
	os.MkdirAll(s.userFiles(u.Name), 0750)
	pp := filepath.Join(s.userPart(u.Name), id)
	var off int64
	if st, err := os.Stat(pp + ".part"); err == nil {
		off = st.Size()
	} else {
		if isNew != nil {
			if msg := isNew(); msg != "" {
				http.Error(w, msg, 403)
				return
			}
		}
		s.mu.Lock()
		if msg := s.checkRoom(u, m.Size); msg != "" {
			s.mu.Unlock()
			http.Error(w, msg, 507)
			return
		}
		b, _ := json.Marshal(m)
		os.WriteFile(pp+".json", b, 0640)
		os.WriteFile(pp+".part", nil, 0640)
		s.mu.Unlock()
	}
	if m.Size == 0 {
		name, err := s.finalize(u.Name, id, m)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, map[string]any{"id": id, "offset": 0, "done": true, "name": name})
		return
	}
	writeJSON(w, map[string]any{"id": id, "offset": off})
}

const maxChunk = 16 << 20

func (s *srv) upChunk(w http.ResponseWriter, r *http.Request) { s.upChunkFor(w, r, userOf(r), nil) }

func (s *srv) upChunkFor(w http.ResponseWriter, r *http.Request, u *user, onDone func(name string, size int64)) {
	id := r.PathValue("id")
	if len(id) != 24 || strings.Trim(id, "0123456789abcdef") != "" {
		http.Error(w, "bad id", 400)
		return
	}
	lk, _ := s.upMu.LoadOrStore(u.Name+"/"+id, &sync.Mutex{})
	lk.(*sync.Mutex).Lock()
	defer lk.(*sync.Mutex).Unlock()

	pp := filepath.Join(s.userPart(u.Name), id)
	var m partMeta
	if err := readJSON(pp+".json", &m); err != nil {
		http.Error(w, "unknown upload", 404)
		return
	}
	off, err := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64)
	f, err2 := os.OpenFile(pp+".part", os.O_WRONLY, 0640)
	if err != nil || err2 != nil {
		http.Error(w, "bad request", 400)
		return
	}
	defer f.Close()
	st, _ := f.Stat()
	if off != st.Size() {
		w.WriteHeader(409)
		writeJSON(w, map[string]any{"offset": st.Size()})
		return
	}
	limit := m.Size - off
	if limit > maxChunk {
		limit = maxChunk
	}
	f.Seek(off, io.SeekStart)
	n, cerr := io.Copy(f, io.LimitReader(r.Body, limit))
	cur := off + n
	if cerr != nil {
		w.WriteHeader(500)
		writeJSON(w, map[string]any{"offset": cur})
		return
	}
	if cur >= m.Size {
		f.Close()
		name, err := s.finalize(u.Name, id, m)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if onDone != nil {
			onDone(name, m.Size)
		}
		writeJSON(w, map[string]any{"offset": cur, "done": true, "name": name})
		return
	}
	writeJSON(w, map[string]any{"offset": cur})
}

// DELETE /api/up/{id} — отмена загрузки: удалить недокачанный кусок.
func (s *srv) upCancel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if len(id) != 24 || strings.Trim(id, "0123456789abcdef") != "" {
		http.Error(w, "bad id", 400)
		return
	}
	u := userOf(r)
	lk, _ := s.upMu.LoadOrStore(u.Name+"/"+id, &sync.Mutex{})
	lk.(*sync.Mutex).Lock()
	defer lk.(*sync.Mutex).Unlock()
	pp := filepath.Join(s.userPart(u.Name), id)
	os.Remove(pp + ".part")
	os.Remove(pp + ".json")
	w.WriteHeader(204)
}

func (s *srv) finalize(owner, id string, m partMeta) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ext := filepath.Ext(m.Name)
	base := strings.TrimSuffix(m.Name, ext)
	name := m.Name
	dst, _, ok := s.dirPath(owner, m.Dir)
	if !ok {
		return "", fmt.Errorf("bad path")
	}
	os.MkdirAll(dst, 0750)
	for i := 2; ; i++ {
		if _, err := os.Stat(filepath.Join(dst, name)); os.IsNotExist(err) {
			break
		}
		name = fmt.Sprintf("%s (%d)%s", base, i, ext)
	}
	pp := filepath.Join(s.userPart(owner), id)
	f, _ := os.OpenFile(pp+".part", os.O_WRONLY, 0640)
	if f != nil {
		f.Sync()
		f.Close()
	}
	if err := os.Rename(pp+".part", filepath.Join(dst, name)); err != nil {
		return "", err
	}
	dur := time.Duration(0)
	if st, err := os.Stat(pp + ".json"); err == nil {
		dur = time.Since(st.ModTime())
	}
	os.Remove(pp + ".json")
	s.upMu.Delete(owner + "/" + id)
	speed := 0.0
	if dur > 0 {
		speed = float64(m.Size) / dur.Seconds() / 1024
	}
	log.Printf("%s: received %q (%d bytes) за %s, %.0f КБ/с", owner, name, m.Size, dur.Round(time.Second), speed)
	return name, nil
}

// Освобождает место под новый файл: удаляет самые старые файлы этого пользователя.
// Учитывает квоту пользователя и общую. Вызывать под s.mu.
// checkRoom — хватает ли места. Старые файлы НЕ удаляются: при нехватке — понятная ошибка.
func (s *srv) checkRoom(u *user, need int64) string {
	uq := s.userQuota(u)
	uUsed, _ := dirSize(s.userFiles(u.Name), s.userPart(u.Name))
	if uUsed+need > uq {
		return fmt.Sprintf("квота заполнена: занято %.0f из %.0f МБ — удалите ненужные файлы", float64(uUsed)/(1<<20), float64(uq)/(1<<20))
	}
	all, _ := dirSize(s.files, s.part)
	if all+need > s.quota {
		return "на сервере закончилось место — попробуйте позже"
	}
	return ""
}

func (s *srv) janitor() {
	for {
		s.pruneThumbs()
		// незавершённые регистрации (без 2FA) старше суток удаляются
		for _, u := range s.users.list() {
			if u.Pending && time.Since(time.Unix(u.Created, 0)) > 24*time.Hour {
				s.users.remove(u.Name)
				os.RemoveAll(s.userFiles(u.Name))
				os.RemoveAll(s.userPart(u.Name))
				log.Printf("removed unfinished registration %q", u.Name)
			}
		}
		ttl := time.Duration(s.cfg.TTLDays) * 24 * time.Hour
		clean := func(dir string, age time.Duration) {
			ents, _ := os.ReadDir(dir)
			for _, e := range ents {
				if i, err := e.Info(); err == nil && time.Since(i.ModTime()) > age {
					os.Remove(filepath.Join(dir, e.Name()))
				}
			}
		}
		for _, u := range s.users.list() {
			if ttl > 0 && !u.Keep {
				filepath.WalkDir(s.userFiles(u.Name), func(p string, d os.DirEntry, err error) error {
					if err == nil && !d.IsDir() {
						if i, e := d.Info(); e == nil && time.Since(i.ModTime()) > ttl {
							os.Remove(p)
						}
					}
					return nil
				})
			}
			clean(s.userPart(u.Name), 24*time.Hour)
		}
		s.pruneShares()
		time.Sleep(time.Hour)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// запрос пришёл по HTTPS (через Cloudflare)
type proxKey struct{}

func isHTTPS(r *http.Request) bool {
	return r.Context().Value(proxKey{}) != nil || r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" || strings.Contains(r.Header.Get("Cf-Visitor"), "https")
}
