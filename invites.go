package main

// Приглашения: одноразовая ссылка на регистрацию, действует сутки.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type invite struct {
	By  string `json:"by"`
	Exp int64  `json:"exp"`
}

type inviteStore struct {
	mu   sync.Mutex
	path string
	m    map[string]invite
}

func newInviteStore(dir string) *inviteStore {
	st := &inviteStore{path: filepath.Join(dir, "invites.json"), m: map[string]invite{}}
	readJSON(st.path, &st.m)
	return st
}

func (st *inviteStore) saveLocked() {
	now := time.Now().Unix()
	for k, v := range st.m {
		if v.Exp < now {
			delete(st.m, k)
		}
	}
	b, _ := json.Marshal(st.m)
	if os.WriteFile(st.path+".tmp", b, 0600) == nil {
		os.Rename(st.path+".tmp", st.path)
	}
}

func (st *inviteStore) create(by string) string {
	b := make([]byte, 12)
	rand.Read(b)
	tok := base64.RawURLEncoding.EncodeToString(b)
	st.mu.Lock()
	defer st.mu.Unlock()
	n := 0
	for _, v := range st.m {
		if v.By == by {
			n++
		}
	}
	if n >= 20 { // не копим: самое старое приглашение этого пользователя уходит
		var oldK string
		var oldE int64 = 1 << 62
		for k, v := range st.m {
			if v.By == by && v.Exp < oldE {
				oldK, oldE = k, v.Exp
			}
		}
		delete(st.m, oldK)
	}
	st.m[tok] = invite{By: by, Exp: time.Now().Add(24 * time.Hour).Unix()}
	st.saveLocked()
	return tok
}

// valid — кто пригласил ("" — приглашения нет или оно истекло)
func (st *inviteStore) valid(tok string) string {
	if tok == "" || len(tok) > 64 {
		return ""
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	v, ok := st.m[tok]
	if !ok || v.Exp < time.Now().Unix() {
		return ""
	}
	return v.By
}

func (st *inviteStore) use(tok string) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	if v, ok := st.m[tok]; !ok || v.Exp < time.Now().Unix() {
		return false
	}
	delete(st.m, tok)
	st.saveLocked()
	return true
}
