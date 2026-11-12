package main

import (
	"bytes"
	"context"
	"encoding/json"
	"image"
	"image/color"
	"image/jpeg"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExtras(t *testing.T) {
	dir, _ := os.MkdirTemp("", "extras") // не TempDir: события пишутся в фоне и после конца теста
	cfg := &Config{DataDir: dir, MaxFileMB: 76, QuotaGB: 1, UserQuotaGB: 1, TTLDays: 7, MaxUsers: 20}
	s := &srv{cfg: cfg, files: filepath.Join(dir, "files"), part: filepath.Join(dir, "part"), maxFile: 76 << 20, quota: 1 << 30, uquota: 1 << 30,
		failures: map[string][]time.Time{}, regs: map[string][]time.Time{}, alerted: map[string]time.Time{}}
	os.MkdirAll(filepath.Join(dir, "meta"), 0750)
	s.secret = []byte("k")
	s.users = newUserStore(filepath.Join(dir, "meta"))
	s.site = newSiteSettings(filepath.Join(dir, "meta"))
	s.sh = newShareStore(filepath.Join(dir, "meta"))
	s.users.upsert("bob", "password1", "-", nil, nil)
	os.MkdirAll(filepath.Join(s.files, "bob", "In"), 0750)
	bob := s.users.get("bob")
	authed := func(r *http.Request) *http.Request {
		return r.WithContext(context.WithValue(r.Context(), userKey{}, bob))
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /s/{token}/auth", s.shareAuth)
	mux.HandleFunc("GET /s/{token}", s.publicShare)
	mux.HandleFunc("POST /s/{token}/up", s.csrf(s.inboxInit))
	mux.HandleFunc("PUT /s/{token}/up/{id}", s.csrf(s.inboxChunk))

	// создать ссылку-приём с паролем
	w := httptest.NewRecorder()
	s.createShare(w, authed(httptest.NewRequest("POST", "/api/shares", strings.NewReader(`{"name":"In","hours":24,"max":2,"kind":"in","password":"secret"}`))))
	var sh map[string]any
	json.Unmarshal(w.Body.Bytes(), &sh)
	tok := sh["token"].(string)
	if sh["kind"] != "in" || sh["pass"] != true {
		t.Fatal(w.Body.String())
	}
	// без пароля — форма
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/s/"+tok, nil))
	if !strings.Contains(w.Body.String(), "Нужен пароль") {
		t.Fatal("no gate")
	}
	// загрузка без пароля — 403
	w = httptest.NewRecorder()
	rq := httptest.NewRequest("POST", "/s/"+tok+"/up", strings.NewReader(`{"name":"a.txt","size":5}`))
	rq.Header.Set("X-Landrop", "1")
	mux.ServeHTTP(w, rq)
	if w.Code != 403 {
		t.Fatal("upload w/o pass", w.Code)
	}
	// неверный и верный пароль
	w = httptest.NewRecorder()
	rq = httptest.NewRequest("POST", "/s/"+tok+"/auth", strings.NewReader(url.Values{"p": {"bad"}}.Encode()))
	rq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	mux.ServeHTTP(w, rq)
	if !strings.Contains(w.Header().Get("Location"), "e=1") {
		t.Fatal("bad pass accepted")
	}
	w = httptest.NewRecorder()
	rq = httptest.NewRequest("POST", "/s/"+tok+"/auth", strings.NewReader(url.Values{"p": {"secret"}}.Encode()))
	rq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	mux.ServeHTTP(w, rq)
	ck := w.Result().Cookies()
	if len(ck) != 1 {
		t.Fatal("no cookie")
	}
	w = httptest.NewRecorder()
	rq = httptest.NewRequest("GET", "/s/"+tok, nil)
	rq.AddCookie(ck[0])
	mux.ServeHTTP(w, rq)
	if !strings.Contains(w.Body.String(), "upload.js") {
		t.Fatal("no inbox page", w.Body.String())
	}
	// загрузка двух файлов, третий — отказ
	up := func(name, body string) int {
		w := httptest.NewRecorder()
		rq := httptest.NewRequest("POST", "/s/"+tok+"/up", strings.NewReader(`{"name":"`+name+`","size":`+itoa(len(body))+`}`))
		rq.Header.Set("X-Landrop", "1")
		rq.AddCookie(ck[0])
		mux.ServeHTTP(w, rq)
		if w.Code != 200 {
			t.Log("init", w.Body.String())
			return w.Code
		}
		var j map[string]any
		json.Unmarshal(w.Body.Bytes(), &j)
		w = httptest.NewRecorder()
		rq = httptest.NewRequest("PUT", "/s/"+tok+"/up/"+j["id"].(string)+"?offset=0", strings.NewReader(body))
		rq.Header.Set("X-Landrop", "1")
		rq.AddCookie(ck[0])
		mux.ServeHTTP(w, rq)
		if w.Code != 200 {
			t.Log(w.Body.String())
		}
		return w.Code
	}
	if c := up("a.txt", "hello"); c != 200 {
		t.Fatal("up1", c)
	}
	if c := up("b.txt", "world!"); c != 200 {
		t.Fatal("up2", c)
	}
	if c := up("c.txt", "xx"); c != 403 {
		t.Fatal("up3 should fail", c)
	}
	if b, _ := os.ReadFile(filepath.Join(s.files, "bob", "In", "a.txt")); string(b) != "hello" {
		t.Fatal("file not saved")
	}
	// приём без «общей папки»: скачать нельзя
	mux.HandleFunc("GET /s/{token}/dl", s.publicDownload)
	w = httptest.NewRecorder()
	rq = httptest.NewRequest("GET", "/s/"+tok+"/dl?p=a.txt", nil)
	rq.AddCookie(ck[0])
	mux.ServeHTTP(w, rq)
	if w.Code != 404 {
		t.Fatal("inbox download must be 404", w.Code)
	}
	// общая папка: видно и скачивается
	w = httptest.NewRecorder()
	s.createShare(w, authed(httptest.NewRequest("POST", "/api/shares", strings.NewReader(`{"name":"In","hours":24,"kind":"in","shared":true}`))))
	json.Unmarshal(w.Body.Bytes(), &sh)
	t2 := sh["token"].(string)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/s/"+t2, nil))
	if !strings.Contains(w.Body.String(), "a.txt") || !strings.Contains(w.Body.String(), "Общая папка") {
		t.Fatal("shared page", w.Body.String())
	}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/s/"+t2+"/dl?p=a.txt", nil))
	if w.Body.String() != "hello" {
		t.Fatal("shared dl", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/s/"+t2+"/dl?p=../../bob/p.jpg", nil))
	if w.Code == 200 {
		t.Fatal("traversal")
	}
	// приглашения: одноразовые
	s.invites = newInviteStore(filepath.Join(dir, "meta"))
	it := s.invites.create("bob")
	if s.invites.valid(it) != "bob" || !s.invites.use(it) || s.invites.use(it) || s.invites.valid(it) != "" {
		t.Fatal("invite")
	}
	// миниатюра с EXIF-поворотом 6
	img := image.NewRGBA(image.Rect(0, 0, 400, 300))
	for y := 0; y < 300; y++ {
		for x := 0; x < 400; x++ {
			img.Set(x, y, color.RGBA{uint8(x / 2), 0, 0, 255})
		}
	}
	var jb bytes.Buffer
	jpeg.Encode(&jb, img, nil)
	os.WriteFile(filepath.Join(s.files, "bob", "p.jpg"), jb.Bytes(), 0640)
	w = httptest.NewRecorder()
	s.thumb(w, authed(httptest.NewRequest("GET", "/api/thumb?name=p.jpg", nil)))
	if w.Code != 200 || w.Header().Get("Content-Type") != "image/jpeg" {
		t.Fatal("thumb", w.Code)
	}
	ti, err := jpeg.Decode(w.Body)
	if err != nil || ti.Bounds().Dx() != thumbSize {
		t.Fatal("thumb decode", err)
	}
	// inline: svg не отдаётся как картинка
	if inlineType("x.svg") != "" || inlineType("x.html") != "" || inlineType("a.JPG") != "image/jpeg" {
		t.Fatal("inline types")
	}
}

func TestExifOrient(t *testing.T) {
	// минимальный JPEG-заголовок с APP1 Exif, orientation=6 (little endian)
	tiff := []byte{'I', 'I', 42, 0, 8, 0, 0, 0, 1, 0, 0x12, 0x01, 3, 0, 1, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0}
	app1 := append([]byte("Exif\x00\x00"), tiff...)
	l := len(app1) + 2
	b := append([]byte{0xFF, 0xD8, 0xFF, 0xE1, byte(l >> 8), byte(l)}, app1...)
	if o := exifOrientation(b); o != 6 {
		t.Fatal(o)
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }
