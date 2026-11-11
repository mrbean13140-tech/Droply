package main

// Для нового интерфейса: длительность видео (MP4/MOV, без библиотек), объём по типам, поиск по имени.

import (
	"encoding/binary"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	extImg = map[string]bool{".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".webp": true, ".heic": true, ".heif": true, ".bmp": true, ".tif": true, ".tiff": true, ".dng": true, ".raw": true}
	extVid = map[string]bool{".mp4": true, ".mov": true, ".m4v": true, ".webm": true, ".mkv": true, ".avi": true, ".3gp": true}
)

func fileKind(name string) string {
	e := strings.ToLower(filepath.Ext(name))
	switch {
	case extImg[e]:
		return "img"
	case extVid[e]:
		return "vid"
	}
	return "other"
}

// ---------- длительность видео ----------

type durEntry struct {
	mt  int64
	sec float64
}

var durCache = struct {
	sync.Mutex
	m map[string]durEntry
}{m: map[string]durEntry{}}

// videoDuration — секунды из moov/mvhd (0 — не удалось). Читает только заголовки атомов.
func videoDuration(p string, st os.FileInfo) float64 {
	e := strings.ToLower(filepath.Ext(p))
	if e != ".mp4" && e != ".mov" && e != ".m4v" && e != ".3gp" {
		return 0
	}
	durCache.Lock()
	if v, ok := durCache.m[p]; ok && v.mt == st.ModTime().UnixNano() {
		durCache.Unlock()
		return v.sec
	}
	durCache.Unlock()
	sec := 0.0
	if f, err := os.Open(p); err == nil {
		sec = mp4Duration(f, st.Size())
		f.Close()
	}
	durCache.Lock()
	if len(durCache.m) > 5000 {
		durCache.m = map[string]durEntry{}
	}
	durCache.m[p] = durEntry{st.ModTime().UnixNano(), sec}
	durCache.Unlock()
	return sec
}

func mp4Duration(r io.ReaderAt, size int64) float64 {
	// верхний уровень: ищем moov (часто в конце файла у iPhone)
	off := int64(0)
	h := make([]byte, 16)
	for i := 0; i < 64 && off+8 <= size; i++ {
		if _, err := r.ReadAt(h[:8], off); err != nil {
			return 0
		}
		n := int64(binary.BigEndian.Uint32(h[:4]))
		typ := string(h[4:8])
		hdr := int64(8)
		if n == 1 {
			if _, err := r.ReadAt(h[8:16], off+8); err != nil {
				return 0
			}
			n, hdr = int64(binary.BigEndian.Uint64(h[8:16])), 16
		} else if n == 0 {
			n = size - off
		}
		if n < hdr {
			return 0
		}
		if typ == "moov" {
			return mvhd(r, off+hdr, off+n)
		}
		off += n
	}
	return 0
}

func mvhd(r io.ReaderAt, start, end int64) float64 {
	h := make([]byte, 8)
	for off := start; off+8 <= end; {
		if _, err := r.ReadAt(h, off); err != nil {
			return 0
		}
		n := int64(binary.BigEndian.Uint32(h[:4]))
		if n < 8 {
			return 0
		}
		if string(h[4:8]) == "mvhd" {
			b := make([]byte, 32)
			if _, err := r.ReadAt(b, off+8); err != nil {
				return 0
			}
			if b[0] == 1 { // version 1: 64-битные времена
				ts := binary.BigEndian.Uint32(b[20:24])
				d := binary.BigEndian.Uint64(b[24:32])
				if ts > 0 {
					return float64(d) / float64(ts)
				}
				return 0
			}
			ts := binary.BigEndian.Uint32(b[12:16])
			d := binary.BigEndian.Uint32(b[16:20])
			if ts > 0 {
				return float64(d) / float64(ts)
			}
			return 0
		}
		off += n
	}
	return 0
}

// ---------- объём по типам (кэш на 30 с) ----------

var kindCache = struct {
	sync.Mutex
	m map[string]kindEntry
}{m: map[string]kindEntry{}}

type kindEntry struct {
	t time.Time
	v map[string]int64
}

func usageByKind(root string) map[string]int64 {
	kindCache.Lock()
	if e, ok := kindCache.m[root]; ok && time.Since(e.t) < 30*time.Second {
		kindCache.Unlock()
		return e.v
	}
	kindCache.Unlock()
	v := map[string]int64{"img": 0, "vid": 0, "other": 0}
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if i, e := d.Info(); e == nil && i.Mode().IsRegular() {
				v[fileKind(d.Name())] += i.Size()
			}
		}
		return nil
	})
	kindCache.Lock()
	kindCache.m[root] = kindEntry{time.Now(), v}
	kindCache.Unlock()
	return v
}

// sharedNames — имена (отн. пути) с живыми ссылками владельца
func (s *srv) sharedNames(owner string) map[string]bool {
	out := map[string]bool{}
	s.sh.mu.Lock()
	defer s.sh.mu.Unlock()
	now := time.Now().Unix()
	for _, sh := range s.sh.m {
		if sh.Owner == owner && sh.Expires > now && (sh.Max == 0 || sh.Kind == "in" || sh.Count < sh.Max) {
			out[sh.Name] = true
		}
	}
	return out
}

// ---------- поиск ----------

type searchHit struct {
	Name  string  `json:"name"`
	Dir   string  `json:"dir"`
	Size  int64   `json:"size"`
	MTime int64   `json:"mtime"`
	IsDir bool    `json:"is_dir,omitempty"`
	Dur   float64 `json:"dur,omitempty"`
}

// GET /api/search?q= — по именам во всех папках пользователя (до 200 совпадений)
func (s *srv) search(w http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	out := []searchHit{}
	if len([]rune(q)) < 2 {
		writeJSON(w, out)
		return
	}
	root := s.userFiles(userOf(r).Name)
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || p == root || len(out) >= 200 {
			return nil
		}
		if !strings.Contains(strings.ToLower(d.Name()), q) {
			return nil
		}
		i, e := d.Info()
		if e != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, filepath.Dir(p))
		if rel == "." {
			rel = ""
		}
		h := searchHit{Name: d.Name(), Dir: filepath.ToSlash(rel), Size: i.Size(), MTime: i.ModTime().Unix(), IsDir: d.IsDir()}
		if !d.IsDir() {
			h.Dur = videoDuration(p, i)
		} else {
			h.Size, _ = treeSize(p)
		}
		out = append(out, h)
		return nil
	})
	sort.Slice(out, func(a, b int) bool { return out[a].MTime > out[b].MTime })
	writeJSON(w, out)
}
