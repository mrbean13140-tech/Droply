package main

// Минимальный ACME-клиент (RFC 8555) для Let's Encrypt с проверкой TLS-ALPN-01:
// сертификат получается и продлевается через тот же порт 443, без порта 80.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const acmeDirURL = "https://acme-v02.api.letsencrypt.org/directory"

type acmeManager struct {
	domain string
	dir    string // /data/meta/acme
	hc     *http.Client

	mu   sync.RWMutex
	cert *tls.Certificate
	chal *tls.Certificate // сертификат для проверки tls-alpn-01

	key   *ecdsa.PrivateKey // ключ аккаунта
	kid   string
	nonce string
	urls  struct{ NewNonce, NewAccount, NewOrder string }
}

func newACME(domain, dataDir string) *acmeManager {
	m := &acmeManager{domain: domain, dir: filepath.Join(dataDir, "meta", "acme"), hc: &http.Client{Timeout: 60 * time.Second}}
	os.MkdirAll(m.dir, 0700)
	m.loadCert()
	go m.loop()
	return m
}

func (m *acmeManager) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	for _, p := range hello.SupportedProtos {
		if p == "acme-tls/1" {
			m.mu.RLock()
			c := m.chal
			m.mu.RUnlock()
			if c == nil {
				return nil, errors.New("no acme challenge")
			}
			return c, nil
		}
	}
	m.mu.RLock()
	c := m.cert
	m.mu.RUnlock()
	if c == nil {
		return nil, errors.New("certificate not ready")
	}
	return c, nil
}

func (m *acmeManager) loadCert() {
	c, err := tls.LoadX509KeyPair(filepath.Join(m.dir, "cert.pem"), filepath.Join(m.dir, "key.pem"))
	if err != nil {
		return
	}
	if c.Leaf == nil && len(c.Certificate) > 0 {
		c.Leaf, _ = x509.ParseCertificate(c.Certificate[0])
	}
	m.mu.Lock()
	m.cert = &c
	m.mu.Unlock()
}

func (m *acmeManager) needRenew() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cert == nil || m.cert.Leaf == nil {
		return true
	}
	if err := m.cert.Leaf.VerifyHostname(m.domain); err != nil {
		return true
	}
	return time.Until(m.cert.Leaf.NotAfter) < 30*24*time.Hour
}

func (m *acmeManager) loop() {
	time.Sleep(5 * time.Second) // дать HTTPS-серверу подняться
	for {
		if m.needRenew() {
			log.Printf("acme: obtaining certificate for %s", m.domain)
			if err := m.obtain(); err != nil {
				log.Printf("acme: %v (повтор через 15 мин)", err)
				time.Sleep(15 * time.Minute)
				continue
			}
			log.Printf("acme: certificate ok for %s", m.domain)
		}
		time.Sleep(12 * time.Hour)
	}
}

// ---- JWS ----

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (m *acmeManager) jwk() map[string]string {
	p := m.key.PublicKey
	pad := func(b []byte) []byte { return append(make([]byte, 32-len(b)), b...) }
	return map[string]string{"crv": "P-256", "kty": "EC", "x": b64(pad(p.X.Bytes())), "y": b64(pad(p.Y.Bytes()))}
}

func (m *acmeManager) thumbprint() string {
	j := m.jwk()
	s := fmt.Sprintf(`{"crv":"%s","kty":"%s","x":"%s","y":"%s"}`, j["crv"], j["kty"], j["x"], j["y"])
	h := sha256.Sum256([]byte(s))
	return b64(h[:])
}

func (m *acmeManager) getNonce() error {
	resp, err := m.hc.Head(m.urls.NewNonce)
	if err != nil {
		return err
	}
	resp.Body.Close()
	m.nonce = resp.Header.Get("Replay-Nonce")
	return nil
}

// post отправляет JWS; payload nil = POST-as-GET.
func (m *acmeManager) post(url string, payload any) (*http.Response, []byte, error) {
	for attempt := 0; attempt < 3; attempt++ {
		if m.nonce == "" {
			if err := m.getNonce(); err != nil {
				return nil, nil, err
			}
		}
		prot := map[string]any{"alg": "ES256", "nonce": m.nonce, "url": url}
		if m.kid != "" {
			prot["kid"] = m.kid
		} else {
			prot["jwk"] = m.jwk()
		}
		pb, _ := json.Marshal(prot)
		var plb []byte
		if payload != nil {
			plb, _ = json.Marshal(payload)
		}
		signing := b64(pb) + "." + b64(plb)
		h := sha256.Sum256([]byte(signing))
		r, s, err := ecdsa.Sign(rand.Reader, m.key, h[:])
		if err != nil {
			return nil, nil, err
		}
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		body, _ := json.Marshal(map[string]string{"protected": b64(pb), "payload": b64(plb), "signature": b64(sig)})
		req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/jose+json")
		resp, err := m.hc.Do(req)
		if err != nil {
			return nil, nil, err
		}
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		m.nonce = resp.Header.Get("Replay-Nonce")
		if resp.StatusCode >= 400 {
			if bytes.Contains(rb, []byte("badNonce")) {
				continue
			}
			return resp, rb, fmt.Errorf("%s: http %d: %s", url, resp.StatusCode, rb)
		}
		return resp, rb, nil
	}
	return nil, nil, errors.New("acme: badNonce repeatedly")
}

func (m *acmeManager) setup() error {
	if m.key == nil {
		kp := filepath.Join(m.dir, "account.pem")
		if b, err := os.ReadFile(kp); err == nil {
			if blk, _ := pem.Decode(b); blk != nil {
				m.key, _ = x509.ParseECPrivateKey(blk.Bytes)
			}
		}
		if m.key == nil {
			k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return err
			}
			der, _ := x509.MarshalECPrivateKey(k)
			os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0600)
			m.key = k
		}
	}
	resp, err := m.hc.Get(acmeDirURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var d struct{ NewNonce, NewAccount, NewOrder string }
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return err
	}
	m.urls = d
	m.kid = ""
	r, _, err := m.post(d.NewAccount, map[string]any{"termsOfServiceAgreed": true})
	if err != nil {
		return err
	}
	m.kid = r.Header.Get("Location")
	return nil
}

func (m *acmeManager) obtain() error {
	if err := m.setup(); err != nil {
		return fmt.Errorf("account: %w", err)
	}
	r, body, err := m.post(m.urls.NewOrder, map[string]any{"identifiers": []map[string]string{{"type": "dns", "value": m.domain}}})
	if err != nil {
		return fmt.Errorf("order: %w", err)
	}
	orderURL := r.Header.Get("Location")
	var order struct {
		Status         string
		Authorizations []string
		Finalize       string
		Certificate    string
	}
	json.Unmarshal(body, &order)

	for _, az := range order.Authorizations {
		_, ab, err := m.post(az, nil)
		if err != nil {
			return err
		}
		var authz struct {
			Status     string
			Challenges []struct{ Type, URL, Token, Status string }
		}
		json.Unmarshal(ab, &authz)
		if authz.Status == "valid" {
			continue
		}
		var chURL, token string
		for _, c := range authz.Challenges {
			if c.Type == "tls-alpn-01" {
				chURL, token = c.URL, c.Token
			}
		}
		if chURL == "" {
			return errors.New("no tls-alpn-01 challenge offered")
		}
		cc, err := m.challengeCert(token + "." + m.thumbprint())
		if err != nil {
			return err
		}
		m.mu.Lock()
		m.chal = cc
		m.mu.Unlock()
		if _, _, err := m.post(chURL, map[string]any{}); err != nil {
			return err
		}
		ok := false
		for i := 0; i < 30; i++ {
			time.Sleep(2 * time.Second)
			_, ab, err := m.post(az, nil)
			if err != nil {
				return err
			}
			json.Unmarshal(ab, &authz)
			if authz.Status == "valid" {
				ok = true
				break
			}
			if authz.Status == "invalid" {
				return fmt.Errorf("authorization invalid: %s", ab)
			}
		}
		m.mu.Lock()
		m.chal = nil
		m.mu.Unlock()
		if !ok {
			return errors.New("authorization timeout")
		}
	}

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: m.domain}, DNSNames: []string{m.domain}}, certKey)
	if err != nil {
		return err
	}
	if _, body, err = m.post(order.Finalize, map[string]string{"csr": b64(csr)}); err != nil {
		return fmt.Errorf("finalize: %w", err)
	}
	json.Unmarshal(body, &order)
	for i := 0; i < 30 && order.Status != "valid"; i++ {
		time.Sleep(2 * time.Second)
		_, body, err := m.post(orderURL, nil)
		if err != nil {
			return err
		}
		json.Unmarshal(body, &order)
		if order.Status == "invalid" {
			return fmt.Errorf("order invalid: %s", body)
		}
	}
	if order.Certificate == "" {
		return errors.New("certificate not issued")
	}
	_, chain, err := m.post(order.Certificate, nil)
	if err != nil {
		return err
	}
	kder, _ := x509.MarshalECPrivateKey(certKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})
	c, err := tls.X509KeyPair(chain, keyPEM)
	if err != nil {
		return err
	}
	c.Leaf, _ = x509.ParseCertificate(c.Certificate[0])
	os.WriteFile(filepath.Join(m.dir, "key.pem"), keyPEM, 0600)
	os.WriteFile(filepath.Join(m.dir, "cert.pem"), chain, 0600)
	m.mu.Lock()
	m.cert = &c
	m.mu.Unlock()
	return nil
}

var oidACMEIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}

func (m *acmeManager) challengeCert(keyAuth string) (*tls.Certificate, error) {
	h := sha256.Sum256([]byte(keyAuth))
	ext, err := asn1.Marshal(h[:])
	if err != nil {
		return nil, err
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber:    big.NewInt(time.Now().UnixNano()),
		Subject:         pkix.Name{CommonName: m.domain},
		DNSNames:        []string{m.domain},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: oidACMEIdentifier, Critical: true, Value: ext}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: crypto.Signer(k)}, nil
}
