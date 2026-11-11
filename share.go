package main

import (
	"archive/zip"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Публичные ссылки: /s/<token> — страница с кнопкой, /s/<token>/dl — скачивание.
// Страница нужна, чтобы превью в мессенджерах не съедали лимит скачиваний.

type share struct {
	Token   string           `json:"token"`
	Owner   string           `json:"owner"`
	Name    string           `json:"name"`
	Created int64            `json:"created"`
	Expires int64            `json:"expires"`
	Max     int              `json:"max"` // 0 = без лимита
	Count   int              `json:"count"`
	Kind    string           `json:"kind,omitempty"`   // "" — раздача, "in" — приём файлов в папку
	Shared  bool             `json:"shared,omitempty"` // для "in": общая папка — по ссылке видно и можно скачать файлы
	Pass    string           `json:"pass,omitempty"`   // соль:хэш пароля (необязательно)
	lastIP  map[string]int64 // когда последний раз уведомляли о скачивании с этого IP
}

type shareStore struct {
	mu   sync.Mutex
	path string
	m    map[string]*share
}

func newShareStore(dir string) *shareStore {
	os.MkdirAll(dir, 0750)
	st := &shareStore{path: filepath.Join(dir, "shares.json"), m: map[string]*share{}}
	var list []*share
	if readJSON(st.path, &list) == nil {
		for _, sh := range list {
			st.m[sh.Token] = sh
		}
	}
	return st
}

func (st *shareStore) saveLocked() {
	list := make([]*share, 0, len(st.m))
	for _, sh := range st.m {
		list = append(list, sh)
	}
	b, _ := json.Marshal(list)
	tmp := st.path + ".tmp"
	if os.WriteFile(tmp, b, 0640) == nil {
		os.Rename(tmp, st.path)
	}
}

// живая ссылка: не истекла, лимит не выбран, файл на месте
func (s *srv) shareAlive(sh *share) bool {
	// у «приёма» лимит проверяется при начале загрузки, иначе обрывалась бы последняя докачка
	if time.Now().Unix() > sh.Expires || (sh.Kind != "in" && sh.Max > 0 && sh.Count >= sh.Max) {
		return false
	}
	if s.users.get(sh.Owner) == nil {
		return false
	}
	if sh.Kind == "in" {
		p, _, ok := s.dirPath(sh.Owner, sh.Name)
		st, err := os.Stat(p)
		return ok && err == nil && st.IsDir()
	}
	p, ok := s.filePath(sh.Owner, sh.Name)
	if !ok {
		return false
	}
	st, err := os.Stat(p)
	return err == nil && (st.Mode().IsRegular() || st.IsDir())
}

func (s *srv) pruneShares() {
	s.sh.mu.Lock()
	defer s.sh.mu.Unlock()
	changed := false
	for t, sh := range s.sh.m {
		if !s.shareAlive(sh) {
			delete(s.sh.m, t)
			changed = true
		}
	}
	if changed {
		s.sh.saveLocked()
	}
}

func baseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" || strings.Contains(r.Header.Get("Cf-Visitor"), "https") {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// pubURL — адрес для внешних ссылок: публичный домен, если настроен (а не LAN-адрес).
func (s *srv) pubURL(r *http.Request) string {
	if s.cfg.TLSDomain != "" {
		return "https://" + s.cfg.TLSDomain
	}
	return baseURL(r)
}

// GET /api/invite -> ссылка на регистрацию + QR.
func (s *srv) invite(w http.ResponseWriter, r *http.Request) {
	tok := s.invites.create(userOf(r).Name)
	u := s.pubURL(r) + "/login.html?step=register&inv=" + tok
	svg, err := qrSVG(u)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, map[string]any{"url": u, "qr": svg, "open": s.users.count() < s.cfg.MaxUsers})
}

func (s *srv) shareJSON(r *http.Request, sh *share) map[string]any {
	isDir := false
	if p, ok := s.filePath(sh.Owner, sh.Name); ok {
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			isDir = true
		}
	}
	return map[string]any{"token": sh.Token, "name": sh.Name, "dir": isDir || sh.Kind == "in", "expires": sh.Expires, "max": sh.Max,
		"count": sh.Count, "url": s.pubURL(r) + "/s/" + sh.Token, "kind": sh.Kind, "pass": sh.Pass != "", "shared": sh.Shared}
}

func (s *srv) createShare(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name   string `json:"name"`
		Hours  int    `json:"hours"`
		Max    int    `json:"max"`
		Kind   string `json:"kind"`
		Pass   string `json:"password"`
		Shared bool   `json:"shared"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req) != nil {
		http.Error(w, "bad request", 400)
		return
	}
	if req.Hours < 1 || req.Hours > 168 {
		req.Hours = 24
	}
	if req.Max < 0 || req.Max > 1000 {
		req.Max = 0
	}
	owner := userOf(r).Name
	if req.Kind == "in" {
		p, rel, ok := s.dirPath(owner, req.Name)
		if st, err := os.Stat(p); !ok || err != nil || !st.IsDir() {
			http.Error(w, "папка не найдена", 404)
			return
		}
		req.Name = rel
	} else {
		req.Kind = ""
		p, ok := s.filePath(owner, req.Name)
		if _, err := os.Stat(p); !ok || err != nil {
			http.Error(w, "file not found", 404)
			return
		}
	}
	b := make([]byte, 16)
	rand.Read(b)
	sh := &share{Token: base64.RawURLEncoding.EncodeToString(b), Owner: owner, Name: req.Name, Created: time.Now().Unix(),
		Expires: time.Now().Add(time.Duration(req.Hours) * time.Hour).Unix(), Max: req.Max, Kind: req.Kind, Shared: req.Kind == "in" && req.Shared}
	if req.Pass != "" {
		if len(req.Pass) > 128 {
			http.Error(w, "слишком длинный пароль", 400)
			return
		}
		salt := make([]byte, 16)
		rand.Read(salt)
		sh.Pass = hex.EncodeToString(salt) + ":" + hashPw(req.Pass, salt)
	}
	s.sh.mu.Lock()
	s.sh.m[sh.Token] = sh
	s.sh.saveLocked()
	s.sh.mu.Unlock()
	writeJSON(w, s.shareJSON(r, sh))
}

func (s *srv) listShares(w http.ResponseWriter, r *http.Request) {
	s.pruneShares()
	s.sh.mu.Lock()
	out := []map[string]any{}
	list := make([]*share, 0, len(s.sh.m))
	me := userOf(r).Name
	for _, sh := range s.sh.m {
		if sh.Owner == me {
			list = append(list, sh)
		}
	}
	sort.Slice(list, func(a, b int) bool { return list[a].Created > list[b].Created })
	for _, sh := range list {
		out = append(out, s.shareJSON(r, sh))
	}
	s.sh.mu.Unlock()
	writeJSON(w, out)
}

func (s *srv) deleteShare(w http.ResponseWriter, r *http.Request) {
	s.sh.mu.Lock()
	if sh, ok := s.sh.m[r.PathValue("token")]; ok && sh.Owner == userOf(r).Name {
		delete(s.sh.m, sh.Token)
		s.sh.saveLocked()
	}
	s.sh.mu.Unlock()
	w.WriteHeader(204)
}

func (s *srv) shareQR(w http.ResponseWriter, r *http.Request) {
	s.sh.mu.Lock()
	sh, ok := s.sh.m[r.PathValue("token")]
	s.sh.mu.Unlock()
	if !ok || sh.Owner != userOf(r).Name {
		http.NotFound(w, r)
		return
	}
	svg, err := qrSVG(s.pubURL(r) + "/s/" + sh.Token)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Write([]byte(svg))
}

// неверные токены считаются как неудачные входы (защита от перебора)
func (s *srv) lookupPublic(w http.ResponseWriter, r *http.Request) (*share, bool) {
	ip := clientIP(r)
	s.limMu.Lock()
	var recent []time.Time
	for _, t := range s.failures[ip] {
		if time.Since(t) < 10*time.Minute {
			recent = append(recent, t)
		}
	}
	s.failures[ip] = recent
	s.limMu.Unlock()
	if len(recent) >= 30 {
		http.Error(w, "too many requests", 429)
		return nil, false
	}
	s.sh.mu.Lock()
	sh, ok := s.sh.m[r.PathValue("token")]
	alive := ok && s.shareAlive(sh)
	s.sh.mu.Unlock()
	if !alive {
		s.fail(ip)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(404)
		w.Write([]byte(publicPage("Ссылка недействительна", "<p class='muted'>Срок действия истёк, лимит скачиваний исчерпан или файл удалён.</p>")))
		return nil, false
	}
	return sh, true
}

func publicPage(title, body string) string {
	return `<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<meta name="robots" content="noindex"><title>` + html.EscapeString(title) + `</title><link rel="stylesheet" href="/style.css"><link rel="icon" href="/icon-192.png?v=4"></head>
<body><main class="pub"><div class="brand"><img src="/icon-192.png" alt=""><span>Droply</span></div>
<h1>` + html.EscapeString(title) + `</h1>` + body + `</main></body></html>`
}

func (s *srv) countDownload(sh *share, r *http.Request) {
	// докачка (Range не с нуля) не считается новым скачиванием
	if rg := r.Header.Get("Range"); rg == "" || strings.HasPrefix(rg, "bytes=0-") {
		s.sh.mu.Lock()
		sh.Count++
		s.sh.saveLocked()
		// уведомление — по каждому новому адресу; с одного и того же IP не чаще раза в 5 минут
		ip := clientIP(r)
		if sh.lastIP == nil {
			sh.lastIP = map[string]int64{}
		}
		n, notify := sh.Count, time.Now().Unix()-sh.lastIP[ip] > 300
		if notify {
			sh.lastIP[ip] = time.Now().Unix()
		}
		s.sh.mu.Unlock()
		if notify {
			lim := ""
			if sh.Max > 0 {
				lim = fmt.Sprintf(" (%d из %d)", n, sh.Max)
			}
			msg, ua, owner := "⬇️ Droply: скачали «"+path.Base(sh.Name)+"»"+lim+"\n", r.UserAgent(), sh.Owner
			go func() { s.notifyUser(owner, msg+who(ua, ip)) }()
		}
	}
}

func (s *srv) publicShare(w http.ResponseWriter, r *http.Request) {
	sh, ok := s.lookupPublic(w, r)
	if !ok || !s.passGate(w, r, sh, true) {
		return
	}
	if sh.Kind == "in" {
		s.inboxPage(w, r, sh)
		return
	}
	p, _ := s.filePath(sh.Owner, sh.Name)
	st, _ := os.Stat(p)
	left := ""
	if sh.Max > 0 {
		left = fmt.Sprintf(" · осталось скачиваний: %d", sh.Max-sh.Count)
	}
	until := time.Unix(sh.Expires, 0).In(msk).Format("02.01 15:04")
	tok := url.PathEscape(sh.Token)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if !st.IsDir() {
		body := fmt.Sprintf(`<ul class="list"><li><div class="info"><div class="name">%s</div><div class="meta">%s · до %s%s</div></div>
<a class="btn" href="/s/%s/dl">Скачать</a></li></ul>`,
			html.EscapeString(path.Base(sh.Name)), humanSize(st.Size()), until, left, tok)
		w.Write([]byte(publicPage("Файл для вас", body)))
		return
	}
	// папка: список файлов (включая вложенные) и архив целиком
	items, n, total := dirListHTML(p, tok)
	body := fmt.Sprintf(`<p class="muted">Папка «%s» · %d файлов · %s · до %s%s</p>
<p><a class="btn" href="/s/%s/zip">Скачать всё (ZIP)</a></p><ul class="list">%s</ul>`,
		html.EscapeString(path.Base(sh.Name)), n, humanSize(total), until, left, tok, items)
	w.Write([]byte(publicPage("Папка для вас", body)))
}

// dirListHTML — строки списка файлов папки (с вложенными, до 500) со ссылками на скачивание.
func dirListHTML(p, tok string) (string, int, int64) {
	var sb strings.Builder
	var total int64
	n := 0
	filepath.WalkDir(p, func(fp string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || n >= 500 {
			return nil
		}
		i, e := d.Info()
		if e != nil || !i.Mode().IsRegular() {
			return nil
		}
		rel, _ := filepath.Rel(p, fp)
		rel = filepath.ToSlash(rel)
		total += i.Size()
		n++
		fmt.Fprintf(&sb, `<li><div class="info"><div class="name">%s</div><div class="meta">%s</div></div><a class="btn" href="/s/%s/dl?p=%s">Скачать</a></li>`,
			html.EscapeString(rel), humanSize(i.Size()), tok, url.QueryEscape(rel))
		return nil
	})
	return sb.String(), n, total
}

// sharePath — путь к файлу/папке ссылки (у «приёма» может быть корень хранилища)
func (s *srv) sharePath(sh *share) string {
	if sh.Kind == "in" {
		p, _, _ := s.dirPath(sh.Owner, sh.Name)
		return p
	}
	p, _ := s.filePath(sh.Owner, sh.Name)
	return p
}

func (s *srv) publicDownload(w http.ResponseWriter, r *http.Request) {
	sh, ok := s.lookupPublic(w, r)
	if !ok || (sh.Kind == "in" && !sh.Shared) || !s.passGate(w, r, sh, false) {
		if ok && sh.Kind == "in" {
			http.NotFound(w, r)
		}
		return
	}
	target := sh.Name
	if sub := r.URL.Query().Get("p"); sub != "" || sh.Kind == "in" {
		p := s.sharePath(sh)
		if st, err := os.Stat(p); err != nil || !st.IsDir() {
			http.NotFound(w, r)
			return
		}
		rel, ok := cleanRel(sub)
		if !ok || rel == "" {
			http.NotFound(w, r)
			return
		}
		target = joinRel(sh.Name, rel)
	}
	if sh.Kind != "in" { // у общей папки Count — число присланных файлов
		s.countDownload(sh, r)
	}
	s.serveFile(w, r, sh.Owner, target)
}

// GET /s/{token}/zip — папка одним архивом (без сжатия, потоком)
func (s *srv) publicZip(w http.ResponseWriter, r *http.Request) {
	sh, ok := s.lookupPublic(w, r)
	if !ok || (sh.Kind == "in" && !sh.Shared) || !s.passGate(w, r, sh, false) {
		if ok && sh.Kind == "in" {
			http.NotFound(w, r)
		}
		return
	}
	p := s.sharePath(sh)
	if st, err := os.Stat(p); err != nil || !st.IsDir() {
		http.NotFound(w, r)
		return
	}
	if sh.Kind != "in" {
		s.countDownload(sh, r)
	}
	name := path.Base(sh.Name) + ".zip"
	if sh.Name == "" {
		name = "Droply.zip"
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename*=UTF-8''"+url.PathEscape(name))
	zw := zip.NewWriter(w)
	defer zw.Close()
	filepath.WalkDir(p, func(fp string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		i, e := d.Info()
		if e != nil || !i.Mode().IsRegular() {
			return nil
		}
		rel, _ := filepath.Rel(p, fp)
		hdr, _ := zip.FileInfoHeader(i)
		hdr.Name = filepath.ToSlash(rel)
		hdr.Method = zip.Store
		zf, e := zw.CreateHeader(hdr)
		if e != nil {
			return e
		}
		f, e := os.Open(fp)
		if e != nil {
			return nil
		}
		io.Copy(zf, f)
		f.Close()
		return nil
	})
}

func humanSize(n int64) string {
	f := float64(n)
	for _, u := range []string{"Б", "КБ", "МБ"} {
		if f < 1024 {
			return fmt.Sprintf("%.0f %s", f, u)
		}
		f /= 1024
	}
	return fmt.Sprintf("%.1f ГБ", f)
}

var msk = time.FixedZone("MSK", 3*3600)
