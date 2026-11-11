'use strict';
const q = new URLSearchParams(location.search);
const step = q.get('step') || 'login';
const $ = s => document.querySelector(s);
const ERR = {
  1: 'Неверный логин или пароль', 2: 'Слишком много попыток, подождите', 3: 'Время входа истекло, войдите заново',
  4: 'Неверный код', 5: 'Регистрация только по приглашению', 6: 'Логин: 2–32 символа, латиница, цифры, . _ -',
  7: 'Слишком простой пароль: нужно от 8 символов, буквы и цифры, без «qwerty», «12345», логина и т. п.', 8: 'Такой логин уже занят', 9: 'Не удалось создать аккаунт',
};
function showErr(t) { const e = $('#err'); e.textContent = t; e.hidden = false; }
if (q.get('e')) showErr(ERR[q.get('e')] || 'Ошибка');

const forms = { login: '#fLogin', code: '#fCode', register: '#fReg', enroll: '#fEnroll' };
const cur = $(forms[step] || forms.login);
cur.hidden = false;
const first = cur.querySelector('input'); if (first) first.focus();
// код из 6 цифр отправляется сам, без кнопки
document.querySelectorAll('input.code').forEach(inp => inp.addEventListener('input', () => {
  const v = inp.value.replace(/\D/g, '');
  if (v.length === 6) { if (inp.id === 'enrollCode') document.getElementById('enrollBtn').click(); else inp.form.submit(); }
}));

const inv = q.get('inv') || '';
if ($('#inv')) $('#inv').value = inv;
fetch('/api/public' + (inv ? '?inv=' + encodeURIComponent(inv) : '')).then(r => r.json()).then(j => {
  $('#toReg').hidden = !j.registration;
  if (step === 'register' && !j.registration) showErr(inv ? 'Приглашение недействительно: истекло или уже использовано. Попросите новое.' : 'Регистрация только по приглашению — попросите ссылку у пользователя Droply.');
}).catch(() => {});

if (step === 'enroll') {
  fetch('/api/2fa/setup', { headers: { 'X-Landrop': '1' } }).then(async r => {
    if (!r.ok) { showErr(await r.text()); return; }
    const j = await r.json();
    $('#totpQr').src = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(j.qr);
    $('#totpSecret').textContent = j.secret.replace(/(.{4})/g, '$1 ').trim();
    $('#totpLink').href = j.uri;
  });
  const go = async () => {
    const r = await fetch('/api/2fa/enable', { method: 'POST', headers: { 'X-Landrop': '1', 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: $('#enrollCode').value }) });
    if (r.ok) location.href = '/'; else showErr(await r.text());
  };
  $('#enrollBtn').onclick = go;
  $('#enrollCode').onkeydown = e => { if (e.key === 'Enter') go(); };
}

// глазик: показать/скрыть пароль
function addEyes(root) {
  root.querySelectorAll('input[type=password]').forEach(inp => {
    if (inp.dataset.eye) return;
    inp.dataset.eye = '1';
    const wrap = document.createElement('div'); wrap.className = 'pw-wrap';
    inp.parentNode.insertBefore(wrap, inp); wrap.appendChild(inp);
    const b = document.createElement('button'); b.type = 'button'; b.className = 'eye'; b.setAttribute('aria-label', 'Показать пароль');
    const open = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg>';
    const shut = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M3 3l18 18M10.6 5.1A10.9 10.9 0 0 1 12 5c6.4 0 10 7 10 7a17 17 0 0 1-3.2 4M6.6 6.6C3.8 8.4 2 12 2 12s3.6 7 10 7a10 10 0 0 0 5.4-1.6M9.9 9.9a3 3 0 0 0 4.2 4.2"/></svg>';
    b.innerHTML = open;
    b.onclick = () => { const show = inp.type === 'password'; inp.type = show ? 'text' : 'password'; b.innerHTML = show ? shut : open; inp.focus(); };
    wrap.appendChild(b);
  });
}
addEyes(document);
