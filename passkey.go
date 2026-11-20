package main

// Вход по Face ID / Touch ID (passkey, WebAuthn) без внешних библиотек: ES256 (P-256), attestation "none".
// Включается из меню аккаунта после обычного входа (пароль + 2FA); дальше на странице входа — «Войти по Face ID».
// Ключи хранятся у пользователя (users.json: passkeys). Работает только по https (домен), в локалке по http — нет.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"

	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type passkey struct {
	ID     string `json:"id"` // base64url
	X      []byte `json:"x"`
	Y      []byte `json:"y"`
	Count  uint32 `json:"count"`
	Device string `json:"device,omitempty"`
	Added  int64  `json:"added"`
	Last   int64  `json:"last,omitempty"`
}

var b64u = base64.RawURLEncoding

type pkChallenge struct {
	ch   []byte
	user string
	kind string
	t    time.Time
}

var pkChal = struct {
	sync.Mutex
	m map[string]pkChallenge
}{m: map[string]pkChallenge{}}

func pkPut(kind, user string) (string, []byte) {
	ch := make([]byte, 32)
	rand.Read(ch)
	idb := make([]byte, 12)
	rand.Read(idb)
	id := b64u.EncodeToString(idb)
	pkChal.Lock()
	defer pkChal.Unlock()
	for k, v := range pkChal.m {
		if time.Since(v.t) > 5*time.Minute {
			delete(pkChal.m, k)
		}
	}
	pkChal.m[id] = pkChallenge{ch, user, kind, time.Now()}
	return id, ch
}

func pkPop(kind, id string) (pkChallenge, error) {
	pkChal.Lock()
	defer pkChal.Unlock()
	v, ok := pkChal.m[id]
	delete(pkChal.m, id)
	if !ok || v.kind != kind || time.Since(v.t) > 5*time.Minute {
		return v, errors.New("запрос устарел, попробуйте ещё раз")
	}
	return v, nil
}

func rpID(r *http.Request) string {
	h := r.Host
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	return strings.ToLower(h)
}

// ---- мини-CBOR (что нужно для attestationObject и COSE-ключа) ----
func cborItem(b []byte) (any, []byte, error) {
	if len(b) == 0 {
		return nil, nil, errors.New("cbor: пусто")
	}
	mt, ai := b[0]>>5, b[0]&31
	b = b[1:]
	var n uint64
	switch {
	case ai < 24:
		n = uint64(ai)
	case ai == 24 && len(b) >= 1:
		n, b = uint64(b[0]), b[1:]
	case ai == 25 && len(b) >= 2:
		n, b = uint64(binary.BigEndian.Uint16(b)), b[2:]
	case ai == 26 && len(b) >= 4:
		n, b = uint64(binary.BigEndian.Uint32(b)), b[4:]
	case ai == 27 && len(b) >= 8:
		n, b = binary.BigEndian.Uint64(b), b[8:]
	default:
		return nil, nil, errors.New("cbor: длина")
	}
	switch mt {
	case 0:
		return int64(n), b, nil
	case 1:
		return -1 - int64(n), b, nil
	case 2, 3:
		if uint64(len(b)) < n {
			return nil, nil, errors.New("cbor: короткие данные")
		}
		if mt == 3 {
			return string(b[:n]), b[n:], nil
		}
		return b[:n], b[n:], nil
	case 4:
		arr := make([]any, 0, n)
		for i := uint64(0); i < n; i++ {
			var v any
			var err error
			if v, b, err = cborItem(b); err != nil {
				return nil, nil, err
			}
			arr = append(arr, v)
		}
		return arr, b, nil
	case 5:
		m := map[any]any{}
		for i := uint64(0); i < n; i++ {
			var k, v any
			var err error
			if k, b, err = cborItem(b); err != nil {
				return nil, nil, err
			}
			if v, b, err = cborItem(b); err != nil {
				return nil, nil, err
			}
			m[k] = v
		}
		return m, b, nil
	case 7:
		return n, b, nil
	}
	return nil, nil, errors.New("cbor: тип")
}

type clientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

func checkClientData(raw []byte, typ string, ch []byte, r *http.Request) error {
	var cd clientData
	if err := json.Unmarshal(raw, &cd); err != nil {
		return errors.New("clientData")
	}
	got, err := b64u.DecodeString(strings.TrimRight(cd.Challenge, "="))
	if err != nil || cd.Type != typ || !bytes.Equal(got, ch) {
		return errors.New("неверный запрос подтверждения")
	}
	if cd.Origin != "https://"+r.Host && cd.Origin != "https://"+rpID(r) {
		return errors.New("чужой адрес: " + cd.Origin)
	}
	return nil
}

// authData: rpIdHash(32) flags(1) count(4) [aaguid(16) idLen(2) id key]
func checkAuthData(ad []byte, r *http.Request) (flags byte, count uint32, err error) {
	if len(ad) < 37 {
		return 0, 0, errors.New("authData")
	}
	h := sha256.Sum256([]byte(rpID(r)))
	if !bytes.Equal(ad[:32], h[:]) {
		return 0, 0, errors.New("чужой rpId")
	}
	flags = ad[32]
	if flags&0x01 == 0 || flags&0x04 == 0 {
		return 0, 0, errors.New("нет подтверждения Face ID")
	}
	return flags, binary.BigEndian.Uint32(ad[33:37]), nil
}

// GET /api/passkey/register/begin (вошедший пользователь)
func (s *srv) pkRegisterBegin(w http.ResponseWriter, r *http.Request) {
	u := userOf(r)
	if !isHTTPS(r) {
		http.Error(w, "Face ID работает только по https-адресу", 400)
		return
	}
	id, ch := pkPut("reg", u.Name)
	var excl []map[string]any
	for _, p := range u.Passkeys {
		excl = append(excl, map[string]any{"type": "public-key", "id": p.ID})
	}
	writeJSON(w, map[string]any{"cid": id, "options": map[string]any{
		"challenge":              b64u.EncodeToString(ch),
		"rp":                     map[string]any{"id": rpID(r), "name": "Droply"},
		"user":                   map[string]any{"id": b64u.EncodeToString([]byte(u.Name)), "name": u.Name, "displayName": u.Name},
		"pubKeyCredParams":       []map[string]any{{"type": "public-key", "alg": -7}},
		"authenticatorSelection": map[string]any{"residentKey": "required", "requireResidentKey": true, "userVerification": "required"},
		"attestation":            "none", "timeout": 120000, "excludeCredentials": excl,
	}})
}

type pkFinishReq struct {
	Cid               string `json:"cid"`
	ID                string `json:"id"`
	Device            string `json:"device"`
	ClientDataJSON    string `json:"clientDataJSON"`
	AttestationObject string `json:"attestationObject"`
	AuthenticatorData string `json:"authenticatorData"`
	Signature         string `json:"signature"`
	UserHandle        string `json:"userHandle"`
}

// POST /api/passkey/register/finish
func (s *srv) pkRegisterFinish(w http.ResponseWriter, r *http.Request) {
	u := userOf(r)
	var req pkFinishReq
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		http.Error(w, "bad request", 400)
		return
	}
	pk, err := func() (*passkey, error) {
		c, err := pkPop("reg", req.Cid)
		if err != nil {
			return nil, err
		}
		if c.user != u.Name {
			return nil, errors.New("чужой запрос")
		}
		cd, err1 := b64u.DecodeString(strings.TrimRight(req.ClientDataJSON, "="))
		ao, err2 := b64u.DecodeString(strings.TrimRight(req.AttestationObject, "="))
		if err1 != nil || err2 != nil {
			return nil, errors.New("плохие данные")
		}
		if err := checkClientData(cd, "webauthn.create", c.ch, r); err != nil {
			return nil, err
		}
		v, _, err := cborItem(ao)
		m, ok := v.(map[any]any)
		if err != nil || !ok {
			return nil, errors.New("attestationObject")
		}
		ad, _ := m["authData"].([]byte)
		flags, count, err := checkAuthData(ad, r)
		if err != nil {
			return nil, err
		}
		if flags&0x40 == 0 || len(ad) < 55 {
			return nil, errors.New("нет данных ключа")
		}
		l := int(binary.BigEndian.Uint16(ad[53:55]))
		if len(ad) < 55+l {
			return nil, errors.New("authData короткий")
		}
		credID := ad[55 : 55+l]
		kv, _, err := cborItem(ad[55+l:])
		key, ok := kv.(map[any]any)
		if err != nil || !ok || key[int64(1)] != int64(2) || key[int64(3)] != int64(-7) || key[int64(-1)] != int64(1) {
			return nil, errors.New("поддерживается только ключ P-256 (ES256)")
		}
		x, _ := key[int64(-2)].([]byte)
		y, _ := key[int64(-3)].([]byte)
		if len(x) != 32 || len(y) != 32 {
			return nil, errors.New("ключ")
		}
		dev := strings.TrimSpace(req.Device)
		if len([]rune(dev)) > 40 {
			dev = string([]rune(dev)[:40])
		}
		return &passkey{ID: b64u.EncodeToString(credID), X: x, Y: y, Count: count, Device: dev, Added: time.Now().Unix()}, nil
	}()
	if err != nil {
		http.Error(w, "Face ID не подключён: "+err.Error(), 400)
		return
	}
	n := 0
	s.users.update(u.Name, func(x *user) { x.Passkeys = append(x.Passkeys, *pk); n = len(x.Passkeys) })
	ua, ip := r.UserAgent(), clientIP(r)
	go func() { s.alertUser(u.Name, "🔐 Включён вход по Face ID: "+who(ua, ip), "/") }()
	writeJSON(w, map[string]any{"ok": true, "count": n})
}

// GET /api/passkey/login/begin (без входа)
func (s *srv) pkLoginBegin(w http.ResponseWriter, r *http.Request) {
	if !isHTTPS(r) {
		http.Error(w, "Face ID работает только по https-адресу", 400)
		return
	}
	id, ch := pkPut("auth", "")
	writeJSON(w, map[string]any{"cid": id, "options": map[string]any{
		"challenge": b64u.EncodeToString(ch), "rpId": rpID(r), "userVerification": "required", "timeout": 120000}})
}

// POST /api/passkey/login/finish (без входа) — после успеха обычная сессия, как после пароля и 2FA
func (s *srv) pkLoginFinish(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if s.tooMany(ip) {
		http.Error(w, "Слишком много попыток, подождите", 429)
		return
	}
	var req pkFinishReq
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		http.Error(w, "bad request", 400)
		return
	}
	name, err := func() (string, error) {
		c, err := pkPop("auth", req.Cid)
		if err != nil {
			return "", err
		}
		uh, _ := b64u.DecodeString(strings.TrimRight(req.UserHandle, "="))
		u := s.users.get(string(uh))
		if u == nil {
			return "", errors.New("ключ не найден — войдите паролем и включите Face ID заново")
		}
		var pk *passkey
		for i := range u.Passkeys {
			if u.Passkeys[i].ID == strings.TrimRight(req.ID, "=") {
				pk = &u.Passkeys[i]
			}
		}
		if pk == nil {
			return "", errors.New("ключ не найден — войдите паролем и включите Face ID заново")
		}
		cd, e1 := b64u.DecodeString(strings.TrimRight(req.ClientDataJSON, "="))
		ad, e2 := b64u.DecodeString(strings.TrimRight(req.AuthenticatorData, "="))
		sig, e3 := b64u.DecodeString(strings.TrimRight(req.Signature, "="))
		if e1 != nil || e2 != nil || e3 != nil {
			return "", errors.New("плохие данные")
		}
		if err := checkClientData(cd, "webauthn.get", c.ch, r); err != nil {
			return "", err
		}
		_, count, err := checkAuthData(ad, r)
		if err != nil {
			return "", err
		}
		h := sha256.Sum256(cd)
		d := sha256.Sum256(append(append([]byte{}, ad...), h[:]...))
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(pk.X), Y: new(big.Int).SetBytes(pk.Y)}
		if !ecdsa.VerifyASN1(pub, d[:], sig) {
			return "", errors.New("подпись не сошлась")
		}
		if pk.Count != 0 && count != 0 && count <= pk.Count {
			return "", errors.New("счётчик ключа не вырос — возможно, ключ скопирован")
		}
		id := pk.ID
		s.users.update(u.Name, func(x *user) {
			for i := range x.Passkeys {
				if x.Passkeys[i].ID == id {
					x.Passkeys[i].Count, x.Passkeys[i].Last = count, time.Now().Unix()
				}
			}
		})
		return u.Name, nil
	}()
	if err != nil {
		s.fail(ip)
		http.Error(w, "Вход не подтверждён: "+err.Error(), 403)
		return
	}
	s.finishLogin(w, r, name)
	writeJSON(w, map[string]any{"ok": true})
}

// DELETE /api/passkey — отключить Face ID на всех устройствах пользователя
func (s *srv) pkClear(w http.ResponseWriter, r *http.Request) {
	u := userOf(r)
	s.users.update(u.Name, func(x *user) { x.Passkeys = nil })
	writeJSON(w, map[string]any{"ok": true})
}
