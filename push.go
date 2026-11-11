package main

// Push-уведомления (Web Push: RFC 8030/8291/8292) и «колокольчик» — лента событий пользователя.
// Без внешних библиотек: VAPID (ES256), шифрование aes128gcm.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var wpb64 = base64.RawURLEncoding

// ---------- VAPID ----------

type vapidKeys struct {
	D   string `json:"d"`   // приватный скаляр (b64url)
	Pub string `json:"pub"` // несжатая точка 65 байт (b64url)
	key *ecdsa.PrivateKey
}

func (s *srv) vapid() *vapidKeys {
	pushMu.Lock()
	defer pushMu.Unlock()
	if s.vk != nil {
		return s.vk
	}
	p := filepath.Join(s.cfg.DataDir, "meta", "vapid.json")
	var v vapidKeys
	if readJSON(p, &v) != nil || v.D == "" {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		v.D = wpb64.EncodeToString(k.D.FillBytes(make([]byte, 32)))
		v.Pub = wpb64.EncodeToString(elliptic.Marshal(elliptic.P256(), k.X, k.Y))
		b, _ := json.Marshal(v)
		os.WriteFile(p, b, 0600)
	}
	d, _ := wpb64.DecodeString(v.D)
	pub, _ := wpb64.DecodeString(v.Pub)
	x, y := elliptic.Unmarshal(elliptic.P256(), pub)
	v.key = &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, D: new(big.Int).SetBytes(d)}
	s.vk = &v
	return s.vk
}

func (s *srv) vapidJWT(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	sub := "mailto:droply@" + s.cfg.TLSDomain
	if s.cfg.TLSDomain == "" {
		sub = "mailto:droply@example.org"
	}
	hdr := wpb64.EncodeToString([]byte(`{"typ":"JWT","alg":"ES256"}`))
	cl, _ := json.Marshal(map[string]any{"aud": u.Scheme + "://" + u.Host, "exp": time.Now().Add(12 * time.Hour).Unix(), "sub": sub})
	in := hdr + "." + wpb64.EncodeToString(cl)
	h := sha256.Sum256([]byte(in))
	r, sg, err := ecdsa.Sign(rand.Reader, s.vapid().key, h[:])
	if err != nil {
		return "", err
	}
	sig := append(r.FillBytes(make([]byte, 32)), sg.FillBytes(make([]byte, 32))...)
	return in + "." + wpb64.EncodeToString(sig), nil
}

// ---------- подписки ----------

type pushSub struct {
	Endpoint string `json:"endpoint"`
	P256dh   string `json:"p256dh"`
	Auth     string `json:"auth"`
	UA       string `json:"ua,omitempty"`
	Created  int64  `json:"created"`
}

var pushMu sync.Mutex

func (s *srv) pushPath() string { return filepath.Join(s.cfg.DataDir, "meta", "push.json") }

func (s *srv) loadSubs() map[string][]pushSub {
	m := map[string][]pushSub{}
	readJSON(s.pushPath(), &m)
	return m
}

func (s *srv) saveSubs(m map[string][]pushSub) {
	b, _ := json.Marshal(m)
	if os.WriteFile(s.pushPath()+".tmp", b, 0600) == nil {
		os.Rename(s.pushPath()+".tmp", s.pushPath())
	}
}

func (s *srv) pushKey(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"key": s.vapid().Pub})
}

func (s *srv) pushSubscribe(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Endpoint string `json:"endpoint"`
		Keys     struct {
			P256dh string `json:"p256dh"`
			Auth   string `json:"auth"`
		} `json:"keys"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req) != nil || !strings.HasPrefix(req.Endpoint, "https://") ||
		len(req.Endpoint) > 1024 || req.Keys.P256dh == "" || req.Keys.Auth == "" {
		http.Error(w, "bad subscription", 400)
		return
	}
	// только известные службы push — сервер не будет слать запросы куда попало
	u, err := url.Parse(req.Endpoint)
	if err != nil || !pushHostOK(u.Hostname()) {
		http.Error(w, "unsupported push service", 400)
		return
	}
	ua := r.UserAgent()
	if len(ua) > 160 {
		ua = ua[:160]
	}
	name := userOf(r).Name
	pushMu.Lock()
	m := s.loadSubs()
	list := m[name][:0:0]
	for _, x := range m[name] {
		if x.Endpoint != req.Endpoint {
			list = append(list, x)
		}
	}
	list = append(list, pushSub{Endpoint: req.Endpoint, P256dh: req.Keys.P256dh, Auth: req.Keys.Auth, UA: ua, Created: time.Now().Unix()})
	if len(list) > 10 {
		list = list[len(list)-10:]
	}
	m[name] = list
	s.saveSubs(m)
	pushMu.Unlock()
	go s.pushOne(name, pushSub{Endpoint: req.Endpoint, P256dh: req.Keys.P256dh, Auth: req.Keys.Auth},
		pushMsg{Title: "Droply", Body: "Уведомления включены на этом устройстве", Tag: "hello"})
	w.WriteHeader(204)
}

func pushHostOK(h string) bool {
	for _, suf := range []string{".push.apple.com", "fcm.googleapis.com", ".push.services.mozilla.com", ".notify.windows.com", "push.yandex.ru"} {
		if h == strings.TrimPrefix(suf, ".") || strings.HasSuffix(h, suf) {
			return true
		}
	}
	return false
}

func (s *srv) pushUnsubscribe(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Endpoint string `json:"endpoint"`
	}
	json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req)
	s.dropSub(userOf(r).Name, req.Endpoint)
	w.WriteHeader(204)
}

func (s *srv) dropSub(name, endpoint string) {
	pushMu.Lock()
	defer pushMu.Unlock()
	m := s.loadSubs()
	list := m[name][:0:0]
	for _, x := range m[name] {
		if x.Endpoint != endpoint {
			list = append(list, x)
		}
	}
	m[name] = list
	s.saveSubs(m)
}

// ---------- отправка ----------

type pushMsg struct {
	Title string `json:"title"`
	Body  string `json:"body"`
	URL   string `json:"url,omitempty"`
	Tag   string `json:"tag,omitempty"`
}

// pushUser — на все устройства пользователя, кроме skip (устройство-источник).
func (s *srv) pushUser(name string, msg pushMsg, skip string) {
	pushMu.Lock()
	subs := append([]pushSub(nil), s.loadSubs()[name]...)
	pushMu.Unlock()
	for _, sb := range subs {
		if sb.Endpoint != skip {
			go s.pushOne(name, sb, msg)
		}
	}
}

var pushClient = &http.Client{Timeout: 20 * time.Second}

func (s *srv) pushOne(name string, sb pushSub, msg pushMsg) {
	payload, _ := json.Marshal(msg)
	body, err := encryptPush(sb, payload)
	if err != nil {
		log.Printf("push %s: %v", name, err)
		return
	}
	jwt, err := s.vapidJWT(sb.Endpoint)
	if err != nil {
		return
	}
	req, _ := http.NewRequest("POST", sb.Endpoint, bytes.NewReader(body))
	req.Header.Set("Content-Encoding", "aes128gcm")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("TTL", "86400")
	req.Header.Set("Urgency", "normal")
	req.Header.Set("Authorization", "vapid t="+jwt+", k="+s.vapid().Pub)
	resp, err := pushClient.Do(req)
	if err != nil {
		log.Printf("push %s: %v", name, err)
		return
	}
	resp.Body.Close()
	switch {
	case resp.StatusCode == 404 || resp.StatusCode == 410: // подписка больше не действует
		s.dropSub(name, sb.Endpoint)
	case resp.StatusCode >= 300:
		log.Printf("push %s: %s", name, resp.Status)
	}
}

func hkdf(salt, ikm, info []byte, n int) []byte {
	m := hmac.New(sha256.New, salt)
	m.Write(ikm)
	prk := m.Sum(nil)
	m = hmac.New(sha256.New, prk)
	m.Write(info)
	m.Write([]byte{1})
	return m.Sum(nil)[:n]
}

// encryptPush — RFC 8291 (aes128gcm, одна запись).
func encryptPush(sb pushSub, payload []byte) ([]byte, error) {
	uaPub, err := wpb64.DecodeString(strings.TrimRight(sb.P256dh, "="))
	if err != nil {
		return nil, err
	}
	auth, err := wpb64.DecodeString(strings.TrimRight(sb.Auth, "="))
	if err != nil || len(auth) != 16 {
		return nil, errors.New("bad auth")
	}
	as, _ := ecdh.P256().GenerateKey(rand.Reader)
	salt := make([]byte, 16)
	rand.Read(salt)
	return encryptPushWith(uaPub, auth, payload, as, salt)
}

func encryptPushWith(uaPub, auth, payload []byte, as *ecdh.PrivateKey, salt []byte) ([]byte, error) {
	peer, err := ecdh.P256().NewPublicKey(uaPub)
	if err != nil {
		return nil, err
	}
	secret, err := as.ECDH(peer)
	if err != nil {
		return nil, err
	}
	asPub := as.PublicKey().Bytes()
	info := append(append([]byte("WebPush: info\x00"), uaPub...), asPub...)
	ikm := hkdf(auth, secret, info, 32)
	cek := hkdf(salt, ikm, []byte("Content-Encoding: aes128gcm\x00"), 16)
	nonce := hkdf(salt, ikm, []byte("Content-Encoding: nonce\x00"), 12)
	blk, _ := aes.NewCipher(cek)
	gcm, _ := cipher.NewGCM(blk)
	ct := gcm.Seal(nil, nonce, append(payload, 2), nil)
	out := make([]byte, 0, 16+4+1+65+len(ct))
	out = append(out, salt...)
	out = binary.BigEndian.AppendUint32(out, 4096)
	out = append(out, byte(len(asPub)))
	out = append(out, asPub...)
	return append(out, ct...), nil
}

// ---------- колокольчик ----------

type event struct {
	ID   string `json:"id"`
	T    int64  `json:"t"`
	Text string `json:"text"`
}

type eventLog struct {
	Seen  int64   `json:"seen"`
	Items []event `json:"items"`
}

var evMu sync.Mutex

func (s *srv) evPath(name string) string {
	return filepath.Join(s.cfg.DataDir, "meta", "events", name+".json")
}

func (s *srv) addEvent(name, text string) {
	evMu.Lock()
	defer evMu.Unlock()
	var l eventLog
	readJSON(s.evPath(name), &l)
	b := make([]byte, 6)
	rand.Read(b)
	l.Items = append([]event{{ID: hex.EncodeToString(b), T: time.Now().Unix(), Text: text}}, l.Items...)
	if len(l.Items) > 50 {
		l.Items = l.Items[:50]
	}
	os.MkdirAll(filepath.Dir(s.evPath(name)), 0750)
	j, _ := json.Marshal(l)
	if os.WriteFile(s.evPath(name)+".tmp", j, 0640) == nil {
		os.Rename(s.evPath(name)+".tmp", s.evPath(name))
	}
}

func (s *srv) listEvents(w http.ResponseWriter, r *http.Request) {
	evMu.Lock()
	var l eventLog
	readJSON(s.evPath(userOf(r).Name), &l)
	evMu.Unlock()
	unread := 0
	for _, e := range l.Items {
		if e.T > l.Seen {
			unread++
		}
	}
	if l.Items == nil {
		l.Items = []event{}
	}
	writeJSON(w, map[string]any{"items": l.Items, "unread": unread, "seen": l.Seen})
}

func (s *srv) seenEvents(w http.ResponseWriter, r *http.Request) {
	name := userOf(r).Name
	evMu.Lock()
	var l eventLog
	readJSON(s.evPath(name), &l)
	l.Seen = time.Now().Unix()
	os.MkdirAll(filepath.Dir(s.evPath(name)), 0750)
	j, _ := json.Marshal(l)
	os.WriteFile(s.evPath(name), j, 0640)
	evMu.Unlock()
	w.WriteHeader(204)
}

// DELETE /api/events — очистить уведомления
func (s *srv) clearEvents(w http.ResponseWriter, r *http.Request) {
	evMu.Lock()
	os.Remove(s.evPath(userOf(r).Name))
	evMu.Unlock()
	w.WriteHeader(204)
}

// event + push одним вызовом: text вида "⬇️ Droply: скачали …"
func (s *srv) alertUser(name, text, url string) {
	body := strings.Replace(text, "Droply: ", "", 1)
	s.addEvent(name, body)
	s.pushUser(name, pushMsg{Title: "Droply", Body: body, URL: url, Tag: fmt.Sprint(time.Now().UnixNano())}, "")
}
