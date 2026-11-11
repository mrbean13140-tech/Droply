package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRenameMove(t *testing.T) {
	dir := t.TempDir()
	s := &srv{cfg: &Config{DataDir: dir}, files: filepath.Join(dir, "files"), part: filepath.Join(dir, "part"),
		failures: map[string][]time.Time{}, alerted: map[string]time.Time{}}
	os.MkdirAll(filepath.Join(dir, "meta"), 0750)
	s.users = newUserStore(filepath.Join(dir, "meta"))
	s.sh = newShareStore(filepath.Join(dir, "meta"))
	s.users.upsert("bob", "password1", "-", nil, nil)
	bob := s.users.get("bob")
	root := filepath.Join(s.files, "bob")
	os.MkdirAll(filepath.Join(root, "A", "Sub"), 0750)
	os.MkdirAll(filepath.Join(root, "B"), 0750)
	os.WriteFile(filepath.Join(root, "A", "x.txt"), []byte("x"), 0640)
	s.sh.m["t1"] = &share{Token: "t1", Owner: "bob", Name: "A/x.txt", Expires: time.Now().Add(time.Hour).Unix()}
	s.sh.m["t2"] = &share{Token: "t2", Owner: "bob", Name: "A", Kind: "in", Expires: time.Now().Add(time.Hour).Unix()}
	call := func(h http.HandlerFunc, body string) (int, string) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/", strings.NewReader(body))
		h(w, r.WithContext(context.WithValue(r.Context(), userKey{}, bob)))
		return w.Code, w.Body.String()
	}
	if c, b := call(s.renameFile, `{"dir":"A","name":"x.txt","to":"y.txt"}`); c != 200 {
		t.Fatal(c, b)
	}
	if s.sh.m["t1"].Name != "A/y.txt" {
		t.Fatal("share not renamed", s.sh.m["t1"].Name)
	}
	if c, _ := call(s.renameFile, `{"dir":"","name":"A","to":"B"}`); c != 409 {
		t.Fatal("rename onto existing must fail", c)
	}
	if c, b := call(s.moveFiles, `{"dir":"","names":["A"],"to":"A/Sub"}`); c != 200 || !strings.Contains(b, "саму себя") {
		t.Fatal("move into itself", c, b)
	}
	c, b := call(s.moveFiles, `{"dir":"","names":["A"],"to":"B"}`)
	var j map[string]any
	json.Unmarshal([]byte(b), &j)
	if c != 200 || j["moved"].(float64) != 1 {
		t.Fatal(c, b)
	}
	if _, err := os.Stat(filepath.Join(root, "B", "A", "y.txt")); err != nil {
		t.Fatal("not moved")
	}
	if s.sh.m["t1"].Name != "B/A/y.txt" || s.sh.m["t2"].Name != "B/A" {
		t.Fatal("shares not moved", s.sh.m["t1"].Name, s.sh.m["t2"].Name)
	}
	if c, _ := call(s.renameFile, `{"dir":"","name":"../etc","to":"z"}`); c == 200 {
		t.Fatal("traversal")
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/tree", nil)
	s.folderTree(w, r.WithContext(context.WithValue(r.Context(), userKey{}, bob)))
	if !strings.Contains(w.Body.String(), `"B/A/Sub"`) {
		t.Fatal(w.Body.String())
	}
}
