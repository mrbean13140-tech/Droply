package main

import "testing"

// RFC 6238 test vector (SHA-1): ключ "12345678901234567890", T=59 -> 94287082 (последние 6: 287082)
func TestTOTP(t *testing.T) {
	sec := b32.EncodeToString([]byte("12345678901234567890"))
	if c := totpCode(sec, 59/30); c != "287082" {
		t.Fatal(c)
	}
	if c := totpCode(sec, 1111111109/30); c != "081804" {
		t.Fatal(c)
	}
}
