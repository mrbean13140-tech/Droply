package main

import (
	"crypto/subtle"
	"encoding/json"
	"html"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const settingsPage = `<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Droply — настройка</title><body style="font:16px system-ui;max-width:520px;margin:40px auto;padding:0 16px">
<h2>Droply — настройка</h2>{MSG}
<p style="color:#666">Туннель: {TUN}. Веб-интерфейс в локальной сети: {LAN}.</p>
<form method="post" style="display:flex;flex-direction:column;gap:12px">
{CUR}
<label>Токен Cloudflare Tunnel (пусто — не менять, «-» — удалить)<br><textarea name="token" rows="3" style="width:100%"></textarea></label>
<label>Разрешённые адреса — VPN-серверы (домен, IP или подсеть, по одному в строке; применяется за 10 минут)<br><textarea name="allow" rows="7" style="width:100%;font:13px monospace">{ALLOW}</textarea></label>
<label>Новый пароль этой страницы (пусто — не менять)<br><input name="password" type="password" autocomplete="new-password" style="width:100%"></label>
<fieldset style="border:1px solid #ccc;border-radius:8px"><legend>Администратор Droply (создать или сбросить пароль)</legend>
<label>Логин<br><input name="admin_user" autocomplete="off" style="width:100%"></label>
<label>Пароль (от 8 символов)<br><input name="admin_pw" type="password" autocomplete="new-password" style="width:100%"></label></fieldset>
<button>Сохранить</button></form></body></html>`

// Страница настройки на :8081. Пока пароль не задан — открыта (первая настройка),
// потом изменения только с текущим паролем.
func runSettings(st *state) {
	addr := st.cfg.SetupListen
	if addr == "" {
		addr = ":8081"
	}
	var failMu sync.Mutex
	var fails []time.Time
	// журнал (только локальная сеть, без секретов: токен передаётся cloudflared через окружение)
	http.HandleFunc("/log", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(logRing.Bytes())
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		msg := ""
		if r.Method == http.MethodPost {
			msg = st.apply(w, r, &failMu, &fails)
		}
		st.mu.Lock()
		c := *st.cfg
		st.mu.Unlock()
		tun, lan, cur := "не настроен", "http://"+c.LanAddr(), ""
		if c.TunnelToken != "" {
			tun = "токен задан"
		}
		if c.Password != "" {
			cur = `<label>Текущий пароль<br><input name="current" type="password" autocomplete="current-password" required style="width:100%"></label>`
		}
		page := strings.NewReplacer("{MSG}", msg, "{TUN}", tun, "{LAN}", html.EscapeString(lan), "{CUR}", cur, "{ALLOW}", html.EscapeString(readAllow(c.DataDir))).Replace(settingsPage)
		w.Write([]byte(page))
	})
	srv := &http.Server{Addr: addr, ReadHeaderTimeout: 10 * time.Second}
	logf("settings page on %s", addr)
	logf("settings: %v", srv.ListenAndServe())
}

func (st *state) apply(w http.ResponseWriter, r *http.Request, failMu *sync.Mutex, fails *[]time.Time) string {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	failMu.Lock()
	var recent []time.Time
	for _, t := range *fails {
		if time.Since(t) < 10*time.Minute {
			recent = append(recent, t)
		}
	}
	*fails = recent
	failMu.Unlock()
	if len(recent) >= 5 {
		return "<p style='color:red'>Слишком много попыток, подождите 10 минут</p>"
	}
	st.mu.Lock()
	cur := st.cfg.Password
	st.mu.Unlock()
	if cur != "" && subtle.ConstantTimeCompare([]byte(r.FormValue("current")), []byte(cur)) != 1 {
		failMu.Lock()
		*fails = append(*fails, time.Now())
		failMu.Unlock()
		time.Sleep(time.Second)
		return "<p style='color:red'>Неверный текущий пароль</p>"
	}
	tok := strings.TrimSpace(r.FormValue("token"))
	if f := strings.Fields(tok); len(f) > 1 { // вставили всю команду — токен последним словом
		tok = f[len(f)-1]
	}
	pw := r.FormValue("password")
	if pw != "" && len(pw) < 8 {
		return "<p style='color:red'>Пароль — минимум 8 символов</p>"
	}
	if cur == "" && pw == "" {
		return "<p style='color:red'>Сначала задайте пароль этой страницы</p>"
	}
	au, ap := strings.ToLower(strings.TrimSpace(r.FormValue("admin_user"))), r.FormValue("admin_pw")
	if au != "" || ap != "" {
		if !nameRe.MatchString(au) || len(ap) < 8 {
			return "<p style='color:red'>Админ: логин 2–32 символа (латиница, цифры, . _ -), пароль от 8 символов</p>"
		}
		bp := st.cfg.DataDir + "/meta/bootstrap.json"
		b, _ := json.Marshal(map[string]string{"name": au, "password": ap})
		os.WriteFile(bp, b, 0600)
		os.Chown(bp, uidServe, uidServe)
	}
	if r.Form.Has("allow") {
		ap := st.cfg.DataDir + "/meta/allow.txt"
		txt := strings.ReplaceAll(r.FormValue("allow"), "\r", "")
		if !strings.HasSuffix(txt, "\n") {
			txt += "\n"
		}
		if err := os.WriteFile(ap, []byte(txt), 0640); err != nil {
			return "<p style='color:red'>" + html.EscapeString(err.Error()) + "</p>"
		}
		os.Chown(ap, uidServe, uidServe)
	}
	st.mu.Lock()
	tokChanged := false
	switch tok {
	case "":
	case "-":
		tokChanged = st.cfg.TunnelToken != ""
		st.cfg.TunnelToken = ""
	default:
		tokChanged = tok != st.cfg.TunnelToken
		st.cfg.TunnelToken = tok
	}
	if pw != "" {
		st.cfg.Password = pw
	}
	b, _ := json.Marshal(map[string]any{"tunnel_token": st.cfg.TunnelToken, "emails": st.cfg.Emails, "password": st.cfg.Password})
	err := os.WriteFile(st.secPath, b, 0600)
	st.mu.Unlock()
	if err != nil {
		return "<p style='color:red'>" + html.EscapeString(err.Error()) + "</p>"
	}
	st.writeServeConfig()
	st.serve.restart()
	if tokChanged {
		st.cf.restart()
	}
	logf("settings saved")
	return "<p style='color:green'>Сохранено, сервис перезапущен</p>"
}

func readAllow(dataDir string) string {
	b, _ := os.ReadFile(dataDir + "/meta/allow.txt")
	return string(b)
}
