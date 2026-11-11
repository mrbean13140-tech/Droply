package main

import "testing"

func TestWeakPw(t *testing.T) {
	for _, p := range []string{"short1a", "qwerty12345", "Password2026", "1111111111a", "abcdefgh12", "bobbob12345", "onlyletters", "1234509876"} {
		if weakPw(p, "bobbob") == "" {
			t.Errorf("%q должен быть слабым", p)
		}
	}
	for _, p := range []string{"Kot-na-krishe7", "x9Fp2mQ7vL", "Синий кит 42 плывёт"} {
		if w := weakPw(p, "bob"); w != "" {
			t.Errorf("%q: %s", p, w)
		}
	}
}
