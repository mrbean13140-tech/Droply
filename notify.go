package main

import (
	"strings"
)

// notify — событие для администраторов (регистрации, тревоги): колокольчик и push.
func (s *srv) notify(text string) {
	for _, u := range s.users.list() {
		if u.Admin {
			s.alertUser(u.Name, text, "/")
		}
	}
}

// uaShort — «iPhone · Safari» из User-Agent
func uaShort(ua string) string {
	dev := "устройство"
	switch {
	case strings.Contains(ua, "iPhone"):
		dev = "iPhone"
	case strings.Contains(ua, "iPad"):
		dev = "iPad"
	case strings.Contains(ua, "Android"):
		dev = "Android"
	case strings.Contains(ua, "Windows"):
		dev = "Windows"
	case strings.Contains(ua, "Mac OS"):
		dev = "Mac"
	case strings.Contains(ua, "Linux"):
		dev = "Linux"
	}
	br := ""
	switch {
	case strings.Contains(ua, "YaBrowser"):
		br = "Яндекс Браузер"
	case strings.Contains(ua, "Edg/"):
		br = "Edge"
	case strings.Contains(ua, "OPR/"):
		br = "Opera"
	case strings.Contains(ua, "Firefox") || strings.Contains(ua, "FxiOS"):
		br = "Firefox"
	case strings.Contains(ua, "CriOS") || strings.Contains(ua, "Chrome"):
		br = "Chrome"
	case strings.Contains(ua, "Safari"):
		br = "Safari"
	}
	if br == "" {
		return dev
	}
	return dev + " · " + br
}
