package main

import (
	"strings"
	"unicode"
)

// Частые пароли (и их основы) — такие не принимаем даже с цифрами в конце.
var commonPw = []string{"password", "passw0rd", "qwerty", "йцукен", "123456", "1234567890", "111111", "000000", "abc123", "iloveyou",
	"admin", "welcome", "monkey", "dragon", "letmein", "football", "master", "sunshine", "princess", "zaq12wsx", "1q2w3e", "qazwsx",
	"asdfgh", "zxcvbn", "пароль", "droply", "incognito", "secret", "parol", "privet", "привет", "love", "test", "user", "login"}

// weakPw — причина, по которой пароль слабый ("" — подходит).
func weakPw(pw, name string) string {
	r := []rune(pw)
	if len(r) < 8 {
		return "пароль — минимум 8 символов"
	}
	if len(r) > 128 {
		return "пароль — не длиннее 128 символов"
	}
	var letter, digit bool
	distinct := map[rune]bool{}
	for _, c := range r {
		distinct[unicode.ToLower(c)] = true
		if unicode.IsLetter(c) {
			letter = true
		}
		if unicode.IsDigit(c) {
			digit = true
		}
	}
	if !letter || !digit {
		return "пароль должен содержать и буквы, и цифры"
	}
	if len(distinct) < 5 {
		return "слишком простой пароль: мало разных символов"
	}
	low := strings.ToLower(pw)
	if name != "" && len(name) >= 3 && strings.Contains(low, strings.ToLower(name)) {
		return "пароль не должен содержать логин"
	}
	for _, c := range commonPw {
		if strings.Contains(low, c) {
			return "слишком простой пароль: содержит «" + c + "»"
		}
	}
	// подряд идущие символы: 1234567, abcdefg
	run := 1
	for i := 1; i < len(r); i++ {
		if r[i] == r[i-1]+1 {
			if run++; run >= 5 {
				return "слишком простой пароль: последовательность символов"
			}
		} else {
			run = 1
		}
	}
	return ""
}
