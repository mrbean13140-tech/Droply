package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func atom(typ string, body []byte) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b, uint32(8+len(body)))
	copy(b[4:], typ)
	return append(b, body...)
}

func TestMP4Duration(t *testing.T) {
	mv := make([]byte, 100) // version 0: timescale@12, duration@16
	binary.BigEndian.PutUint32(mv[12:], 600)
	binary.BigEndian.PutUint32(mv[16:], 600*42)
	file := append(atom("ftyp", []byte("qt  0000")), atom("mdat", make([]byte, 5000))...)
	file = append(file, atom("moov", atom("mvhd", mv))...)
	if d := mp4Duration(bytes.NewReader(file), int64(len(file))); d != 42 {
		t.Fatal(d)
	}
}
