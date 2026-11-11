package main

import (
	"bytes"
	"os"
	"sync"
)

// Кольцевой журнал последних строк (в контейнере нет shell — смотреть логи больше негде).
type ring struct {
	mu  sync.Mutex
	buf []byte
	max int
}

var logRing = &ring{max: 64 << 10}

func (r *ring) Write(p []byte) (int, error) {
	r.mu.Lock()
	r.buf = append(r.buf, p...)
	if len(r.buf) > r.max {
		cut := len(r.buf) - r.max
		if i := bytes.IndexByte(r.buf[cut:], '\n'); i >= 0 {
			cut += i + 1
		}
		r.buf = append([]byte(nil), r.buf[cut:]...)
	}
	r.mu.Unlock()
	return os.Stdout.Write(p)
}

func (r *ring) Bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.buf...)
}
