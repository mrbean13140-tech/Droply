package main

// Дополнения: пароль на ссылку, приём файлов по ссылке, миниатюры, просмотр,

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"image"
	"image/color"
	_ "image/gif"
	"image/jpeg"
	_ "image/png"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"

	"path/filepath"
	"strings"
	"time"
)

// ---------- пароль на ссылку ----------

func (s *srv) passSig(sh *share) string {
	m := hmac.New(sha256.New, s.secret)
	m.Write([]byte("share|" + sh.Token + "|" + sh.Pass))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// passGate: пропускает, если пароля нет или он уже введён (cookie). page=true — показать форму.
func (s *srv) passGate(w http.ResponseWriter, r *http.Request, sh *share, page bool) bool {
	if sh.Pass == "" {
		return true
	}
	if c, err := r.Cookie("sp" + sh.Token); err == nil && hmac.Equal([]byte(c.Value), []byte(s.passSig(sh))) {
		return true
	}
	if !page {
		http.Redirect(w, r, "/s/"+url.PathEscape(sh.Token), http.StatusSeeOther)
		return false
	}
	msg := ""
	if r.URL.Query().Get("e") == "1" {
		msg = `<p class="err">Неверный пароль</p>`
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(publicPage("Нужен пароль", msg+`<form class="card" method="post" action="/s/`+url.PathEscape(sh.Token)+`/auth">
<input type="password" name="p" placeholder="Пароль" autocomplete="off" required autofocus>
<button class="primary">Открыть</button></form>`)))
	return false
}

func (s *srv) shareAuth(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if s.tooMany(ip) {
		http.Error(w, "слишком много попыток, подождите", 429)
		return
	}
	sh, ok := s.lookupPublic(w, r)
	if !ok {
		return
	}
	back := "/s/" + url.PathEscape(sh.Token)
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	pw := r.FormValue("p")
	parts := strings.SplitN(sh.Pass, ":", 2)
	salt, _ := hex.DecodeString(parts[0])
	if len(parts) != 2 || !hmac.Equal([]byte(hashPw(pw, salt)), []byte(parts[1])) {
		s.fail(ip)
		http.Redirect(w, r, back+"?e=1", http.StatusSeeOther)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "sp" + sh.Token, Value: s.passSig(sh), Path: back, HttpOnly: true,
		Secure: isHTTPS(r), SameSite: http.SameSiteLaxMode, MaxAge: 86400})
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// ---------- приём файлов по ссылке ----------

func (s *srv) inboxPage(w http.ResponseWriter, r *http.Request, sh *share) {
	u := s.users.get(sh.Owner)
	left := ""
	if sh.Max > 0 {
		left = fmt.Sprintf(" · осталось файлов: %d", sh.Max-sh.Count)
	}
	until := time.Unix(sh.Expires, 0).In(msk).Format("02.01 15:04")
	title, intro, list := "Отправить файлы", "просит прислать файлы", ""
	if sh.Shared {
		title, intro = "Общая папка", "приглашает в общую папку — смотрите, скачивайте и добавляйте файлы"
		items, n, total := dirListHTML(s.sharePath(sh), url.PathEscape(sh.Token))
		if n == 0 {
			list = `<p class="muted">Пока пусто — добавьте первый файл.</p>`
		} else {
			list = fmt.Sprintf(`<p class="muted">%d файлов · %s · <a href="/s/%s/zip">скачать всё (ZIP)</a></p><ul class="list">%s</ul>`,
				n, humanSize(total), url.PathEscape(sh.Token), items)
		}
	}
	body := fmt.Sprintf(`<p class="muted">%s `+intro+` · до %s · один файл до %s%s</p>
<label id="drop" class="drop"><input id="pick" type="file" multiple>
<span class="drop-icon" aria-hidden="true"><svg viewBox="0 0 64 64"><circle cx="32" cy="32" r="24" fill="currentColor"/><path d="M23 36l9-9 9 9" fill="none" stroke="var(--tile)" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/></svg></span>
<span class="big">Выбрать файлы</span><span class="hint">нажми или перетащи</span></label>
<ul id="queue" class="list" data-token="%s" data-max="%d" data-shared="%t"></ul>%s<script src="/upload.js"></script>`,
		html.EscapeString(sh.Owner), until, humanSize(s.userMaxFile(u)), left, html.EscapeString(sh.Token), s.userMaxFile(u), sh.Shared, list)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(publicPage(title, body)))
}

// общий вход для загрузок по ссылке: живая ссылка «приём», пароль введён
func (s *srv) inboxShare(w http.ResponseWriter, r *http.Request) (*share, *user, bool) {
	sh, ok := s.lookupPublic(w, r)
	if !ok {
		return nil, nil, false
	}
	if sh.Kind != "in" {
		http.NotFound(w, r)
		return nil, nil, false
	}
	if sh.Pass != "" {
		if c, err := r.Cookie("sp" + sh.Token); err != nil || !hmac.Equal([]byte(c.Value), []byte(s.passSig(sh))) {
			http.Error(w, "нужен пароль", 403)
			return nil, nil, false
		}
	}
	u := s.users.get(sh.Owner)
	if u == nil {
		http.NotFound(w, r)
		return nil, nil, false
	}
	return sh, u, true
}

func (s *srv) inboxInit(w http.ResponseWriter, r *http.Request) {
	sh, u, ok := s.inboxShare(w, r)
	if !ok {
		return
	}
	var m partMeta
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&m); err != nil || m.Size < 0 {
		http.Error(w, "bad request", 400)
		return
	}
	m.Dir = sh.Name
	s.upInitFor(w, r, u, m, func() string {
		s.sh.mu.Lock()
		defer s.sh.mu.Unlock()
		if sh.Max > 0 && sh.Count >= sh.Max {
			return "лимит файлов по этой ссылке исчерпан"
		}
		sh.Count++
		s.sh.saveLocked()
		return ""
	})
}

func (s *srv) inboxChunk(w http.ResponseWriter, r *http.Request) {
	sh, u, ok := s.inboxShare(w, r)
	if !ok {
		return
	}
	s.upChunkFor(w, r, u, func(name string, size int64) {
		where := "«Мои файлы»"
		if sh.Name != "" {
			where = "«" + sh.Name + "»"
		}
		log.Printf("%s: inbox %s got %q from %s", u.Name, sh.Token[:6], name, clientIP(r))
		msg, ua, ip, nm := "📥 Droply: в "+where+" прислали файл «"+name+"» ("+humanSize(size)+")\n", r.UserAgent(), clientIP(r), u.Name
		go func() { s.notifyUser(nm, msg+who(ua, ip)) }()
	})
}

// ---------- просмотр и миниатюры ----------

var inlineTypes = map[string]string{
	".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png", ".gif": "image/gif", ".webp": "image/webp",
	".heic": "image/heic", ".heif": "image/heif", ".bmp": "image/bmp",
	".mp4": "video/mp4", ".m4v": "video/mp4", ".mov": "video/quicktime", ".webm": "video/webm",
	".mp3": "audio/mpeg", ".m4a": "audio/mp4", ".aac": "audio/aac", ".wav": "audio/wav", ".ogg": "audio/ogg", ".flac": "audio/flac",
	".pdf": "application/pdf", ".txt": "text/plain; charset=utf-8", ".md": "text/plain; charset=utf-8", ".log": "text/plain; charset=utf-8",
}

// inlineType: тип для показа в браузере. HTML/SVG сюда не входят — иначе чужой файл выполнил бы скрипт на нашем домене.
func inlineType(name string) string { return inlineTypes[strings.ToLower(filepath.Ext(name))] }

var thumbSem = make(chan struct{}, 1) // по одной миниатюре за раз; фото до 30 Мп (~45 МБ памяти при декодировании)

const thumbSize = 256 // хватает и для списка, и для плитки галереи на экранах 3x

func (s *srv) thumb(w http.ResponseWriter, r *http.Request) {
	u := userOf(r)
	rel := joinRel(strings.Trim(r.URL.Query().Get("dir"), "/"), r.URL.Query().Get("name"))
	p, ok := s.filePath(u.Name, rel)
	ext := strings.ToLower(filepath.Ext(p))
	if !ok || (ext != ".jpg" && ext != ".jpeg" && ext != ".png" && ext != ".gif") {
		http.NotFound(w, r)
		return
	}
	st, err := os.Stat(p)
	if err != nil || !st.Mode().IsRegular() || st.Size() > 80<<20 {
		http.NotFound(w, r)
		return
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d|%s|%d|%d", thumbSize, rel, st.Size(), st.ModTime().UnixNano())))
	dir := filepath.Join(s.cfg.DataDir, "meta", "thumbs", u.Name)
	tp := filepath.Join(dir, hex.EncodeToString(sum[:12])+".jpg")
	serve := func() {
		w.Header().Set("Content-Type", "image/jpeg")
		w.Header().Set("Cache-Control", "private, max-age=86400")
		http.ServeFile(w, r, tp)
	}
	if _, err := os.Stat(tp); err == nil {
		now := time.Now()
		os.Chtimes(tp, now, now)
		serve()
		return
	}
	select {
	case thumbSem <- struct{}{}:
	case <-r.Context().Done():
		return
	}
	defer func() { <-thumbSem }()
	if _, err := os.Stat(tp); err == nil { // пока ждали, сделал другой запрос
		serve()
		return
	}
	if err := makeThumb(p, tp, dir); err != nil {
		http.NotFound(w, r)
		return
	}
	serve()
}

func makeThumb(src, dst, dir string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	cfg, _, err := image.DecodeConfig(f)
	if err != nil || cfg.Width*cfg.Height > 30e6 || cfg.Width == 0 || cfg.Height == 0 {
		return fmt.Errorf("bad image")
	}
	orient := 1
	if strings.HasSuffix(strings.ToLower(src), "g") { // jpg/jpeg (png/gif без EXIF — orient 1)
		f.Seek(0, io.SeekStart)
		head := make([]byte, 128<<10)
		n, _ := io.ReadFull(f, head)
		orient = exifOrientation(head[:n])
	}
	f.Seek(0, io.SeekStart)
	img, _, err := image.Decode(f)
	if err != nil {
		return err
	}
	b := img.Bounds()
	side := b.Dx()
	if b.Dy() < side {
		side = b.Dy()
	}
	x0, y0 := b.Min.X+(b.Dx()-side)/2, b.Min.Y+(b.Dy()-side)/2
	out := image.NewRGBA(image.Rect(0, 0, thumbSize, thumbSize))
	const k = 4 // 4×4 отсчёта на пиксель — без «лесенки»
	S := thumbSize
	for y := 0; y < S; y++ {
		for x := 0; x < S; x++ {
			sx, sy := x, y
			switch orient { // EXIF-поворот (кадр квадратный)
			case 2:
				sx = S - 1 - x
			case 3:
				sx, sy = S-1-x, S-1-y
			case 4:
				sy = S - 1 - y
			case 5:
				sx, sy = y, x
			case 6:
				sx, sy = y, S-1-x
			case 7:
				sx, sy = S-1-y, S-1-x
			case 8:
				sx, sy = S-1-y, x
			}
			var rr, gg, bb uint32
			for j := 0; j < k; j++ {
				for i := 0; i < k; i++ {
					px := x0 + (sx*k+i)*side/(S*k)
					py := y0 + (sy*k+j)*side/(S*k)
					c1, c2, c3, _ := img.At(px, py).RGBA()
					rr += c1
					gg += c2
					bb += c3
				}
			}
			out.SetRGBA(x, y, color.RGBA{uint8(rr / (k * k) >> 8), uint8(gg / (k * k) >> 8), uint8(bb / (k * k) >> 8), 255})
		}
	}
	os.MkdirAll(dir, 0750)
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, out, &jpeg.Options{Quality: 78}); err != nil {
		return err
	}
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0640); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// exifOrientation: тег 0x0112 из APP1/Exif JPEG; 1 — если не найден.
func exifOrientation(b []byte) int {
	if len(b) < 4 || b[0] != 0xFF || b[1] != 0xD8 {
		return 1
	}
	i := 2
	for i+4 <= len(b) {
		if b[i] != 0xFF {
			return 1
		}
		mk := b[i+1]
		ln := int(binary.BigEndian.Uint16(b[i+2:]))
		if mk == 0xDA || ln < 2 {
			return 1
		}
		seg := b[i+4 : min(len(b), i+2+ln)]
		if mk == 0xE1 && len(seg) > 14 && string(seg[:6]) == "Exif\x00\x00" {
			t := seg[6:]
			var bo binary.ByteOrder = binary.BigEndian
			if string(t[:2]) == "II" {
				bo = binary.LittleEndian
			}
			off := int(bo.Uint32(t[4:]))
			if off+2 > len(t) {
				return 1
			}
			n := int(bo.Uint16(t[off:]))
			for e := 0; e < n; e++ {
				p := off + 2 + e*12
				if p+12 > len(t) {
					return 1
				}
				if bo.Uint16(t[p:]) == 0x0112 {
					v := int(bo.Uint16(t[p+8:]))
					if v >= 1 && v <= 8 {
						return v
					}
					return 1
				}
			}
			return 1
		}
		i += 2 + ln
	}
	return 1
}

// ---------- уведомления пользователю ----------

func (s *srv) notifyUser(name, text string) { s.alertUser(name, text, "/") } // колокольчик + push

// чистка устаревших миниатюр (вызывается из janitor)
func (s *srv) pruneThumbs() {
	root := filepath.Join(s.cfg.DataDir, "meta", "thumbs")
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if i, e := d.Info(); e == nil && time.Since(i.ModTime()) > 14*24*time.Hour {
				os.Remove(p)
			}
		}
		return nil
	})
}
