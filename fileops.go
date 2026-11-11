package main

// Переименование и перемещение файлов/папок; дерево папок для выбора, куда переместить.

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// reshare — ссылки на переименованный/перемещённый файл или папку продолжают работать
func (s *srv) reshare(owner, oldRel, newRel string) {
	s.sh.mu.Lock()
	defer s.sh.mu.Unlock()
	changed := false
	for _, sh := range s.sh.m {
		if sh.Owner != owner {
			continue
		}
		if sh.Name == oldRel {
			sh.Name, changed = newRel, true
		} else if strings.HasPrefix(sh.Name, oldRel+"/") {
			sh.Name, changed = newRel+sh.Name[len(oldRel):], true
		}
	}
	if changed {
		s.sh.saveLocked()
	}
}

// POST /api/files/rename {dir, name, to}
func (s *srv) renameFile(w http.ResponseWriter, r *http.Request) {
	var req struct{ Dir, Name, To string }
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req) != nil {
		http.Error(w, "bad request", 400)
		return
	}
	u := userOf(r).Name
	dir := strings.Trim(req.Dir, "/")
	to := cleanName(req.To)
	oldRel, newRel := joinRel(dir, req.Name), joinRel(dir, to)
	src, ok1 := s.filePath(u, oldRel)
	dst, ok2 := s.filePath(u, newRel)
	if !ok1 || !ok2 || to == "" {
		http.Error(w, "недопустимое имя", 400)
		return
	}
	if _, err := os.Stat(src); err != nil {
		http.Error(w, "не найдено", 404)
		return
	}
	if oldRel == newRel {
		writeJSON(w, map[string]string{"name": to})
		return
	}
	if _, err := os.Stat(dst); err == nil && !strings.EqualFold(oldRel, newRel) {
		http.Error(w, "такое имя уже есть", 409)
		return
	}
	s.mu.Lock()
	err := os.Rename(src, dst)
	s.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.reshare(u, oldRel, newRel)
	writeJSON(w, map[string]string{"name": to})
}

// POST /api/files/move {dir, names[], to}
func (s *srv) moveFiles(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Dir   string   `json:"dir"`
		Names []string `json:"names"`
		To    string   `json:"to"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req) != nil || len(req.Names) == 0 || len(req.Names) > 500 {
		http.Error(w, "bad request", 400)
		return
	}
	u := userOf(r).Name
	dir := strings.Trim(req.Dir, "/")
	tp, to, ok := s.dirPath(u, strings.Trim(req.To, "/"))
	if st, err := os.Stat(tp); !ok || err != nil || !st.IsDir() {
		http.Error(w, "папка назначения не найдена", 404)
		return
	}
	var failed []string
	moved := 0
	for _, n := range req.Names {
		oldRel, newRel := joinRel(dir, n), joinRel(to, filepath.Base(n))
		src, ok1 := s.filePath(u, oldRel)
		dst, ok2 := s.filePath(u, newRel)
		if !ok1 || !ok2 || oldRel == newRel {
			continue
		}
		if to == oldRel || strings.HasPrefix(to, oldRel+"/") { // папку в саму себя нельзя
			failed = append(failed, n+": нельзя переместить папку в саму себя")
			continue
		}
		if _, err := os.Stat(dst); err == nil {
			failed = append(failed, n+": такое имя уже есть в папке назначения")
			continue
		}
		s.mu.Lock()
		err := os.Rename(src, dst)
		s.mu.Unlock()
		if err != nil {
			failed = append(failed, n+": "+err.Error())
			continue
		}
		s.reshare(u, oldRel, newRel)
		moved++
	}
	writeJSON(w, map[string]any{"moved": moved, "failed": failed})
}

// GET /api/tree — все папки пользователя (относительные пути)
func (s *srv) folderTree(w http.ResponseWriter, r *http.Request) {
	root := s.userFiles(userOf(r).Name)
	out := []string{}
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() || p == root || len(out) >= 2000 {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	writeJSON(w, out)
}
