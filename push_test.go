package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/sha256"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// RFC 8291, приложение A
func TestPushRFC8291(t *testing.T) {
	d := func(s string) []byte {
		b, err := wpb64.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	as, err := ecdh.P256().NewPrivateKey(d("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := encryptPushWith(d("BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"),
		d("BTBZMqHH6r4Tts7J_aSIgg"), []byte("When I grow up, I want to be a watermelon"), as, d("DGv6ra1nlYgDCS1FRnbzlw"))
	if err != nil {
		t.Fatal(err)
	}
	want := "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN"
	if got := wpb64.EncodeToString(out); got != want {
		t.Fatalf("\ngot  %s\nwant %s", got, want)
	}
}

func TestVapidJWT(t *testing.T) {
	s := &srv{cfg: &Config{DataDir: t.TempDir(), TLSDomain: "files.example.ru"}}
	os.MkdirAll(filepath.Join(s.cfg.DataDir, "meta"), 0750)
	j, err := s.vapidJWT("https://web.push.apple.com/abc")
	if err != nil {
		t.Fatal(err)
	}
	p := strings.Split(j, ".")
	h := sha256.Sum256([]byte(p[0] + "." + p[1]))
	sig, _ := wpb64.DecodeString(p[2])
	k := s.vapid().key
	if !ecdsa.Verify(&k.PublicKey, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("bad sig")
	}
	cl, _ := wpb64.DecodeString(p[1])
	if !strings.Contains(string(cl), `"aud":"https://web.push.apple.com"`) {
		t.Fatal(string(cl))
	}
	s2 := &srv{cfg: s.cfg} // ключи переживают перезапуск
	if s2.vapid().Pub != s.vapid().Pub {
		t.Fatal("key not persisted")
	}
}
