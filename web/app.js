'use strict';
const $ = s => document.querySelector(s);
const CHUNK = 8 * 1024 * 1024;
const H = { 'X-Landrop': '1' };
let maxFile = Infinity;
let cwd = '';
const rel = n => cwd ? cwd + '/' + n : n;
const FOLDER = '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M3 6.5A2.5 2.5 0 0 1 5.5 4h3.6l2 2H18.5A2.5 2.5 0 0 1 21 8.5v9a2.5 2.5 0 0 1-2.5 2.5h-13A2.5 2.5 0 0 1 3 17.5z"/></svg>';

const SV = d => `<svg class="ic" viewBox="0 0 24 24">${d}</svg>`;
const FI = { // иконки типов файлов (линейные, в одном стиле)
  folder: SV('<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>'),
  file: SV('<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8zM14 3v5h5"/>'),
  doc: SV('<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8zM14 3v5h5M9 13h6M9 17h4"/>'),
  sheet: SV('<path d="M4 5a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2zM4 9h16M4 15h16M10 3v18"/>'),
  slides: SV('<path d="M3 5h18v11H3zM12 16v4M8 20h8"/>'),
  img: SV('<path d="M4 5h16v14H4z"/><circle cx="9" cy="10" r="1.6"/><path d="M20 16l-5-5-8 8"/>'),
  vid: SV('<path d="M4 6h11v12H4zM15 10l5-3v10l-5-3"/>'),
  aud: SV('<path d="M9 18V5l11-2v13"/><circle cx="6.5" cy="18" r="2.5"/><circle cx="17.5" cy="16" r="2.5"/>'),
  zip: SV('<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8zM14 3v5h5M11 6h1M11 9h1M11 12h1M10 15h2v3h-2z"/>'),
  app: SV('<path d="M5 4h14v16H5zM9 17h6"/>'),
  link: SV('<path d="M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1"/>'),
  chev: SV('<path d="M9 6l6 6-6 6"/>'),
};
const ICONS = {
  down: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 4v11m-5-5 5 5 5-5M5 20h14"/></svg>',
  share: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/></svg>',
  del: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 6l12 12M18 6 6 18"/></svg>',
  more: '<svg viewBox="0 0 24 24" fill="currentColor"><circle cx="5" cy="12" r="2"/><circle cx="12" cy="12" r="2"/><circle cx="19" cy="12" r="2"/></svg>',
  qr: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h2v2h-2zM18 18h2v2h-2zM14 18h2M18 14h2"/></svg>',
};
const TYPES = [
  [/^(jpe?g|png|gif|webp|heic|heif|bmp|svg)$/, 'IMG', '#f97316,#f43f5e'],
  [/^(mp4|mov|mkv|avi|webm|m4v)$/, 'VID', '#8b5cf6,#6366f1'],
  [/^(mp3|m4a|wav|flac|ogg|aac)$/, 'AUD', '#ec4899,#a855f7'],
  [/^(pdf)$/, 'PDF', '#ef4444,#f97316'],
  [/^(docx?|odt|rtf|txt|md|pages)$/, 'DOC', '#3b82f6,#06b6d4'],
  [/^(xlsx?|csv|ods|numbers)$/, 'XLS', '#10b981,#22c55e'],
  [/^(pptx?|key|odp)$/, 'PPT', '#f59e0b,#ef4444'],
  [/^(zip|rar|7z|tar|gz|tgz)$/, 'ZIP', '#64748b,#475569'],
  [/^(apk|ipa|exe|msi|dmg)$/, 'APP', '#14b8a6,#0ea5e9'],
];

function fmt(n) {
  const u = ['Б', 'КБ', 'МБ', 'ГБ'];
  let i = 0;
  while (n >= 1024 && i < 3) { n /= 1024; i++; }
  return (i ? n.toFixed(1) : n) + ' ' + u[i];
}
function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
}
function iconBtn(icon, title, cls) {
  const b = el('button', 'icon-btn' + (cls ? ' ' + cls : ''));
  b.innerHTML = ICONS[icon]; b.title = title; b.setAttribute('aria-label', title);
  return b;
}
const KIND = { IMG: 'img', VID: 'vid', AUD: 'aud', PDF: 'doc', DOC: 'doc', XLS: 'sheet', PPT: 'slides', ZIP: 'zip', APP: 'app' };
function docIcon(name) {
  const ext = (name.includes('.') ? name.split('.').pop() : '').toUpperCase().slice(0, 4);
  const b = el('div', 'dic');
  b.innerHTML = '<svg viewBox="0 0 34 40"><path class="pg" d="M5.5 1.5h15.2l9.3 9.3V36a2.5 2.5 0 0 1-2.5 2.5H5.5A2.5 2.5 0 0 1 3 36V4a2.5 2.5 0 0 1 2.5-2.5z"/><path class="fold" d="M20.7 1.5V8a2.8 2.8 0 0 0 2.8 2.8H30"/></svg>';
  b.append(el('em', '', ext || 'FILE'));
  return b;
}
function badge(name) {
  const ext = (name.split('.').pop() || '').toLowerCase();
  const t = TYPES.find(t => t[0].test(ext));
  const b = el('div', 'badge fi'); b.innerHTML = FI[t ? KIND[t[1]] : 'file'];
  return b;
}
function ago(ts) {
  const d = (Date.now() / 1000 - ts) / 60;
  if (d < 1) return 'только что';
  if (d < 60) return Math.round(d) + ' мин назад';
  if (d < 1440) return Math.round(d / 60) + ' ч назад';
  return new Date(ts * 1000).toLocaleDateString('ru', { day: 'numeric', month: 'short' });
}
function left(ts) {
  const m = (ts - Date.now() / 1000) / 60;
  if (m < 60) return 'ещё ' + Math.max(1, Math.round(m)) + ' мин';
  if (m < 1440) return 'ещё ' + Math.round(m / 60) + ' ч';
  return 'ещё ' + Math.round(m / 1440) + ' дн';
}
let toastT;
// Тост поверх открытых окон: popover попадает в верхний слой, иначе модальный dialog его закрывает.
function toast(t) {
  const e = $('#toast'); e.textContent = t;
  clearTimeout(toastT);
  if (e.showPopover) { e.setAttribute('popover', 'manual'); try { e.hidePopover(); } catch {} e.hidden = false; e.showPopover(); }
  else e.hidden = false;
  requestAnimationFrame(() => e.classList.add('show'));
  toastT = setTimeout(() => {
    e.classList.remove('show');
    setTimeout(() => { try { e.hidePopover && e.hidePopover(); } catch {} e.hidden = true; }, 200);
  }, 1800);
}
// копирование с отметкой ✓ на самой кнопке
async function copyText(text, btn, input) {
  let ok = true;
  try { await navigator.clipboard.writeText(text); }
  catch { try { input.select(); ok = document.execCommand('copy'); } catch { ok = false; } }
  if (btn) {
    const was = btn.innerHTML; btn.innerHTML = ok ? '✓' : '✕'; btn.classList.add(ok ? 'done' : 'fail');
    setTimeout(() => { btn.innerHTML = was; btn.classList.remove('done', 'fail'); }, 1500);
  }
  toast(ok ? 'Скопировано' : 'Не удалось скопировать');
}
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function api(method, url, body, headers, signal) {
  const r = await fetch(url, { method, body, signal, headers: Object.assign({}, H, headers), credentials: 'same-origin' });
  if (r.status === 401) { location.href = '/login.html'; throw new Error('auth'); }
  return r;
}
const jsonHdr = { 'Content-Type': 'application/json' };

// ---- загрузка ----
// PUT куска через XHR: fetch не умеет прогресс отправки, а без него полоса прыгает по 8 МБ.
function putChunk(url, blob, sig, onp) {
  return new Promise((res, rej) => {
    const x = new XMLHttpRequest();
    x.open('PUT', url);
    for (const k in H) x.setRequestHeader(k, H[k]);
    // сторож: нет прогресса 30 с — соединение умерло (например, телефон засыпал), пробуем заново
    let dog = setTimeout(function bark() { x.stalled = true; x.abort(); }, 30000);
    const pet = () => { clearTimeout(dog); dog = setTimeout(() => { x.stalled = true; x.abort(); }, 30000); };
    liveXHR.add(x);
    x.onloadend = () => { clearTimeout(dog); liveXHR.delete(x); };
    x.upload.onprogress = e => { pet(); onp(e.loaded); };
    x.onload = () => {
      if (x.status === 401) { location.href = '/login.html'; rej(new Error('auth')); return; }
      let j = {}; try { j = JSON.parse(x.responseText); } catch {}
      res({ status: x.status, ok: x.status >= 200 && x.status < 300, j });
    };
    x.onerror = x.ontimeout = () => rej(new Error('сеть'));
    x.onabort = () => rej(new Error(x.stalled ? 'сеть' : 'отменено'));
    sig.addEventListener('abort', () => x.abort(), { once: true });
    x.send(blob);
  });
}
async function upload(file) {
  const dir = cwd;
  const li = el('li');
  const info = el('div', 'info');
  const meta = el('div', 'meta', 'подготовка…');
  const bar = el('div', 'bar'); const fill = el('i'); bar.append(fill);
  info.append(el('div', 'name', file.name), meta, bar);
  const ctl = new AbortController(); let id = null;
  const stop = iconBtn('del', 'Отменить', 'del');
  stop.onclick = () => {
    ctl.abort(); li.remove();
    if (id) api('DELETE', '/api/up/' + id).catch(() => {});
  };
  li.append(badge(file.name), info, stop); $('#queue').prepend(li);
  const sig = ctl.signal;
  // плавный прогресс: обновление не чаще 4 раз в секунду, скорость сглажена
  let lastT = 0, lastB = 0, speed = 0, shown = 0;
  const show = (sent, force) => {
    const now = Date.now();
    if (!force && now - lastT < 250) return;
    if (lastT) {
      const dt = (now - lastT) / 1000, inst = Math.max(0, sent - lastB) / dt;
      speed = speed ? speed * 0.8 + inst * 0.2 : inst;
    }
    lastT = now; lastB = sent; shown = Math.max(shown, sent);
    fill.style.width = (shown / file.size * 100).toFixed(1) + '%';
    const left = speed > 0 ? Math.round((file.size - shown) / speed) : 0;
    meta.textContent = `${fmt(shown)} из ${fmt(file.size)}` + (speed > 0 ? ` · ${fmt(speed)}/с` + (left > 3 ? ` · ~${left >= 60 ? Math.round(left / 60) + ' мин' : left + ' с'}` : '') : '');
  };
  try {
    if (file.size > maxFile) throw new Error('больше лимита ' + fmt(maxFile));
    let r = await api('POST', '/api/up', JSON.stringify({ name: file.name, size: file.size, dir }), jsonHdr, sig);
    if (!r.ok) throw new Error(await r.text());
    let offset, done; ({ offset, done, id } = await r.json());
    meta.textContent = 'загрузка…'; show(offset, true);
    let fails = 0;
    while (!done) {
      const end = Math.min(offset + CHUNK, file.size);
      try {
        const base = offset;
        r = await putChunk(`/api/up/${id}?offset=${offset}`, file.slice(offset, end), sig, n => show(base + n));
        const j = r.j;
        if (r.ok || r.status === 409 || r.status >= 500) {
          if (typeof j.offset === 'number') offset = j.offset;
          done = !!j.done;
          if (!r.ok && r.status !== 409) throw new Error('HTTP ' + r.status);
          fails = 0;
        } else throw Object.assign(new Error('HTTP ' + r.status), { fatal: true });
      } catch (e) {
        if (sig.aborted || e.fatal || ++fails > 30) throw e;
        meta.textContent = 'нет связи, повтор…';
        await nap(Math.min(2000 * fails, 15000));
        if (sig.aborted) throw new Error('отменено');
        const s = await api('POST', '/api/up', JSON.stringify({ name: file.name, size: file.size, dir }), jsonHdr, sig).catch(() => null);
        if (s && s.ok) offset = (await s.json()).offset;
        continue;
      }
      show(offset);
    }
    stop.remove();
    fill.style.width = '100%';
    meta.textContent = `готово · ${fmt(file.size)}`; meta.classList.add('okc');
    setTimeout(() => li.remove(), 2500);
    loadFiles();
  } catch (e) {
    if (sig.aborted) return;
    meta.textContent = 'ошибка: ' + e.message;
    meta.classList.add('err');
    bar.remove();
    stop.title = 'Убрать';
  }
}
// Пока идёт загрузка — не даём экрану гаснуть (iOS 16.4+, Android): при блокировке телефон усыпляет страницу.
let active = 0, wakeLock = null;
async function keepAwake() {
  if (!active || document.hidden || wakeLock || !('wakeLock' in navigator)) return;
  try { wakeLock = await navigator.wakeLock.request('screen'); wakeLock.addEventListener('release', () => { wakeLock = null; }); } catch {}
}
function releaseAwake() { if (!active && wakeLock) { wakeLock.release().catch(() => {}); wakeLock = null; } }
// При возврате в приложение после блокировки: оборвать «зависшие» запросы и сразу продолжить с места остановки.
const wakers = new Set(), liveXHR = new Set(); let hiddenAt = 0;
document.addEventListener('visibilitychange', () => {
  if (document.hidden) { hiddenAt = Date.now(); return; }
  keepAwake();
  if (hiddenAt && Date.now() - hiddenAt > 3000) for (const x of liveXHR) { x.stalled = true; x.abort(); }
  for (const w of [...wakers]) w();
});
const nap = ms => new Promise(r => { const w = () => { clearTimeout(t); wakers.delete(w); r(); }; const t = setTimeout(w, ms); wakers.add(w); });
async function runQueue(files) {
  // до 3 файлов параллельно — быстрее на мобильной связи
  const q = [...files];
  active++; keepAwake();
  if (!('wakeLock' in navigator)) toast('Не блокируйте экран до конца загрузки');
  const worker = async () => { while (q.length) await upload(q.shift()); };
  try { await Promise.all([worker(), worker(), worker()]); }
  finally { active--; releaseAwake(); }
}

// ---- списки ----
function renderCrumbs() {
  const nav = $('#crumbs'); nav.replaceChildren();
  const parts = cwd ? cwd.split('/') : [];
  const mk = (label, path) => { const b = el('button', '', label); b.onclick = () => openDir(path); return b; };
  nav.append(mk('Мои файлы', ''));
  parts.forEach((p, i) => { nav.append(el('span', '', '›'), mk(p, parts.slice(0, i + 1).join('/'))); });
}
function openDir(path) { cwd = path; loadFiles(); }

function hello(name) {
  const h = new Date().getHours();
  const g = h >= 5 && h < 12 ? 'Доброе утро' : h >= 12 && h < 17 ? 'Добрый день' : h >= 17 && h < 23 ? 'Добрый вечер' : 'Доброй ночи';
  $('#hello').textContent = g + (name ? ', ' + name : '');
}
function storage(j) {
  const [num, unit] = fmt(j.used).split(' ');
  $('#stUsed').textContent = num.replace('.', ',');
  $('#stOf').textContent = unit + ' из ' + fmt(j.quota).replace('.0 ', ' ');
  $('#stKeep').textContent = j.keep ? 'бессрочно' : j.ttl_days + ' дн.';
  const k = j.by_kind || {}, pc = v => Math.min(100, (v || 0) / j.quota * 100).toFixed(2) + '%';
  $('#segImg').style.width = pc(k.img); $('#segVid').style.width = pc(k.vid); $('#segOth').style.width = pc(k.other);
  $('#lgImg').textContent = fmt(k.img || 0); $('#lgVid').textContent = fmt(k.vid || 0); $('#lgOth').textContent = fmt(k.other || 0);
}
const isMedia = f => !f.dir && (VIEW.img.test(f.name) || VIEW.vid.test(f.name));
const dur = s => { s = Math.round(s); return Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0'); };
function dayGroup(ts) {
  const d = new Date(ts * 1000), now = new Date(), t0 = new Date(now.getFullYear(), now.getMonth(), now.getDate()) / 1000;
  if (ts >= t0) return 'Сегодня';
  if (ts >= t0 - 86400) return 'Вчера';
  if (ts >= t0 - 6 * 86400) return 'На этой неделе';
  const m = d.toLocaleDateString('ru', { month: 'long', year: d.getFullYear() === now.getFullYear() ? undefined : 'numeric' });
  return m[0].toUpperCase() + m.slice(1);
}
const plural = (n, a, b, c) => n % 10 === 1 && n % 100 !== 11 ? a : n % 10 >= 2 && n % 10 <= 4 && (n % 100 < 10 || n % 100 >= 20) ? b : c;
function secHead(title, note) {
  const h = el('div', 'sec'); h.append(el('b', '', title)); if (note) h.append(el('span', '', note)); return h;
}
function thumbURL(f, dir) { return '/api/thumb?name=' + encodeURIComponent(f.name) + (dir ? '&dir=' + encodeURIComponent(dir) : '') + '&v=' + f.mtime; }
function fileRow(f, dir, onOpen) {
  const li = el('li', 'clickable');
  const b = f.dir ? (() => { const x = el('div', 'badge fi fold'); x.innerHTML = FI.folder; return x; })() : (isMedia(f) ? badge(f.name) : docIcon(f.name));
  const info = el('div', 'info');
  const meta = f.dir ? `${f.count || 0} ${plural(f.count || 0, 'файл', 'файла', 'файлов')} · ${fmt(f.size)}` : `${fmt(f.size)} · ${ago(f.mtime)}`;
  info.append(el('div', 'name', f.name), el('div', 'meta', (dir !== undefined && dir !== cwd ? '/' + (dir || 'Мои файлы') + ' · ' : '') + meta));
  if (f.shared) { const s = el('span', 'lk'); s.innerHTML = FI.link; s.title = 'Есть ссылка'; info.firstChild.append(s); }
  const acts = el('div', 'row-acts');
  const mo = iconBtn('more', 'Ещё', 'more'); mo.onclick = e => { e.stopPropagation(); openFileMenu(f); };
  acts.append(mo);
  if (f.dir) { const c = el('span', 'chev'); c.innerHTML = FI.chev; acts.append(c); }
  li.onclick = e => { if (!e.target.closest('.row-acts .icon-btn')) onOpen(); };
  li.append(b, info, acts);
  return li;
}
function mediaTile(f) {
  const t = el('div', 't clickable');
  if (/\.(jpe?g|png|gif)$/i.test(f.name)) {
    const im = el('img'); im.loading = 'lazy'; im.alt = ''; im.src = thumbURL(f, cwd);
    im.onerror = () => { im.remove(); t.classList.add('noimg'); t.insertAdjacentHTML('afterbegin', FI.img); };
    t.append(im);
  } else { t.classList.add('noimg'); t.innerHTML = VIEW.vid.test(f.name) ? FI.vid : FI.img; }
  if (VIEW.vid.test(f.name)) t.append(el('span', 'dur', f.dur ? dur(f.dur) : '▶'));
  if (f.shared) { const s = el('span', 'tlk'); s.innerHTML = FI.link; t.append(s); }
  const mo = el('button', 'tmore'); mo.innerHTML = ICONS.more; mo.title = 'Ещё';
  mo.onclick = e => { e.stopPropagation(); openFileMenu(f); };
  t.append(mo);
  t.onclick = () => openView(f);
  return t;
}
let recentList = [];
let recentView = 'tile'; try { recentView = localStorage.getItem('recentView') === 'list' ? 'list' : 'tile'; } catch (e) {}
function recentOpen(h) { if (h.dir === cwd) { const x = curFiles.find(y => y.name === h.name); if (x) return isMedia(x) || VIEW.doc.test(x.name) ? openView(x) : openFileMenu(x); } pendingOpen = h.name; openDir(h.dir); }
function recentRow(h) {
  const li = el('li', 'clickable'), c = recentCard(h), p = c.querySelector('.p');
  p.querySelectorAll('.dur,.tlk').forEach(x => x.remove()); p.classList.add('rth');
  const info = el('div', 'info'); info.append(el('div', 'name', h.name), el('div', 'meta', fmt(h.size) + ' · ' + ago(h.mtime) + (h.dir ? ' · ' + h.dir : '')));
  li.append(p, info); li.onclick = () => recentOpen(h); return li;
}
function recentCard(h) {
  const c = el('div', 'rc clickable');
  const p = el('div', 'p');
  const f = { name: h.name, size: h.size, mtime: h.mtime, dur: h.dur };
  if (/\.(jpe?g|png|gif)$/i.test(h.name)) {
    const im = el('img'); im.loading = 'lazy'; im.alt = ''; im.src = thumbURL(f, h.dir);
    im.onerror = () => { im.remove(); p.classList.add('noimg'); p.innerHTML = FI.img; };
    p.append(im);
  } else if (isMedia(f)) { p.classList.add('noimg'); p.innerHTML = VIEW.vid.test(h.name) ? FI.vid : FI.img; }
  else { p.classList.add('noimg', 'docp'); p.append(docIcon(h.name)); }
  if (VIEW.vid.test(h.name)) p.append(el('span', 'dur', h.dur ? dur(h.dur) : '▶'));
  if (h.shared) { const s = el('span', 'tlk'); s.innerHTML = FI.link; p.append(s); }
  c.append(p, el('div', 'n', h.name), el('div', 'm', fmt(h.size) + ' · ' + ago(h.mtime)));
  c.onclick = () => recentOpen(h);
  return c;
}
function renderFiles(list) {
  const root = $('#fileView'); root.replaceChildren();
  if (false) { // «Недавние» скрыты по просьбе владельца
    const hd = secHead('Недавние'), vw = el('div', 'rview');
    [['tile', '<svg class="ic" viewBox="0 0 24 24"><rect x="4" y="4" width="7" height="7" rx="1.5"/><rect x="13" y="4" width="7" height="7" rx="1.5"/><rect x="4" y="13" width="7" height="7" rx="1.5"/><rect x="13" y="13" width="7" height="7" rx="1.5"/></svg>', 'Плитка'],
     ['list', '<svg class="ic" viewBox="0 0 24 24"><path d="M8 6h12M8 12h12M8 18h12"/><circle cx="4" cy="6" r=".8"/><circle cx="4" cy="12" r=".8"/><circle cx="4" cy="18" r=".8"/></svg>', 'Список']].forEach(([k, ic, t]) => {
      const b = el('button', k === recentView ? 'on' : ''); b.innerHTML = ic; b.title = t; b.setAttribute('aria-label', t);
      b.onclick = () => { recentView = k; try { localStorage.setItem('recentView', k); } catch (e) {} renderFiles(curFiles); };
      vw.append(b);
    });
    hd.append(vw); root.append(hd);
    if (recentView === 'list') { const ul = el('ul', 'list card rlist'); recentList.slice(0, 6).forEach(h => ul.append(recentRow(h))); root.append(ul); }
    else { const strip = el('div', 'recent'); recentList.forEach(h => strip.append(recentCard(h))); root.append(strip); }
  }
  const folders = list.filter(f => f.dir), media = list.filter(isMedia), docs = list.filter(f => !f.dir && !isMedia(f));
  if (folders.length) {
    root.append(secHead('Папки', folders.length + ''));
    const ul = el('ul', 'list card'); folders.forEach(f => ul.append(fileRow(f, undefined, () => openDir(rel(f.name))))); root.append(ul);
  }
  if (media.length) {
    const byDate = fSort === 'new' || fSort === 'old';
    const groups = [];
    for (const f of media) {
      const g = byDate ? dayGroup(f.mtime) : 'Фото и видео';
      if (!groups.length || groups[groups.length - 1][0] !== g) groups.push([g, []]);
      groups[groups.length - 1][1].push(f);
    }
    for (const [g, fs] of groups) {
      root.append(secHead(byDate ? g : (fType === 'vid' ? 'Видео' : fType === 'img' ? 'Фото' : 'Фото и видео'), fs.length + ''));
      const grid = el('div', 'tiles'); fs.forEach(f => grid.append(mediaTile(f))); root.append(grid);
    }
  }
  if (docs.length) {
    root.append(secHead('Документы', docs.length + ''));
    const ul = el('ul', 'list card'); docs.forEach(f => ul.append(fileRow(f, undefined, () => openView(f)))); root.append(ul);
  }
}
let curFiles = [], gridMode = false;
async function loadFiles() {
  if (searching()) return runSearch();
  const [r, rr] = [await api('GET', '/api/files?dir=' + encodeURIComponent(cwd)), null];
  if (r.status === 404 && cwd) { cwd = ''; return loadFiles(); }
  if (rr && rr.ok) recentList = await rr.json();
  const j = await r.json();
  maxFile = j.max_file;
  $('#limit').textContent = fmt(j.max_file);
  storage(j);
  $('#cntFiles').textContent = j.files.length;
  renderCrumbs(); if (!cwd) $('#crumbs').replaceChildren(); // в корне путь не нужен
  curFiles = arrange(j.files);
  renderFiles(curFiles);
  if (pendingOpen) { const f = curFiles.find(x => x.name === pendingOpen); pendingOpen = null; if (f) (isMedia(f) || VIEW.doc.test(f.name) ? openView(f) : openFileMenu(f)); }
  $('#empty').hidden = curFiles.length > 0;
  $('#empty').innerHTML = j.files.length ? 'Здесь нет файлов этого типа.' : 'Здесь пока пусто.<br>Нажмите ＋, чтобы загрузить файлы.';
}

// ---- поиск ----
const searching = () => $('#q').value.trim().length >= 2;
let sT = 0, pendingOpen = null;
async function runSearch() {
  const q = $('#q').value.trim();
  const r = await api('GET', '/api/search?q=' + encodeURIComponent(q)); const hits = await r.json();
  if ($('#q').value.trim() !== q) return; // уже ввели другое
  $('#crumbs').replaceChildren(el('span', 'srch', 'Найдено: ' + hits.length));
  const root = $('#fileView'); root.replaceChildren();
  $('#empty').hidden = hits.length > 0; $('#empty').textContent = 'Ничего не найдено.';
  if (!hits.length) return;
  const ul = el('ul', 'list card');
  for (const h of hits) {
    const f = { name: h.name, size: h.size, mtime: h.mtime, dir: h.is_dir, dur: h.dur };
    ul.append(fileRow(f, h.dir, () => {
      $('#q').value = ''; $('#qx').hidden = true;
      if (f.dir) { openDir(h.dir ? h.dir + '/' + h.name : h.name); return; }
      pendingOpen = f.name; openDir(h.dir);
    }));
  }
  root.append(ul);
}
$('#q').addEventListener('input', () => { $('#qx').hidden = !$('#q').value; clearTimeout(sT); sT = setTimeout(loadFiles, 250); });

// ---- фильтр по типу и сортировка ----
let fType = 'all', fSort = 'new';
try { fType = localStorage.getItem('droply-type') || 'all'; if (fType === 'other') fType = 'doc'; fSort = localStorage.getItem('droply-sort') || 'new'; } catch {}
const DOCRE = /\.(pdf|docx?|xlsx?|pptx?|txt|md|rtf|odt|ods|csv|log)$/i;
function arrange(list) {
  const isImg = f => VIEW.img.test(f.name), isVid = f => VIEW.vid.test(f.name);
  let out = list.filter(f => {
    if (fType === 'all') return true;
    if (fType === 'dir') return !!f.dir;
    if (f.dir) return false;
    if (fType === 'img') return isImg(f);
    if (fType === 'vid') return isVid(f);
    return !isImg(f) && !isVid(f); // документы и всё остальное
  });
  const cmp = ({ new: (a, b) => b.mtime - a.mtime, old: (a, b) => a.mtime - b.mtime, name: (a, b) => a.name.localeCompare(b.name, 'ru', { numeric: true }),
    size: (a, b) => b.size - a.size, small: (a, b) => a.size - b.size })[fSort] || ((a, b) => b.mtime - a.mtime);
  return out.sort((a, b) => (!!b.dir - !!a.dir) || cmp(a, b)); // папки сверху
}
function syncFilterUI() {
  document.querySelectorAll('#typeChips button').forEach(b => b.classList.toggle('on', b.dataset.t === fType));
  $('#sortSel').value = fSort;
}
$('#typeChips').onclick = e => {
  const b = e.target.closest('button'); if (!b) return;
  fType = b.dataset.t; try { localStorage.setItem('droply-type', fType); } catch {}
  syncFilterUI(); loadFiles();
};
$('#sortSel').onchange = e => {
  fSort = e.target.value;
  try { localStorage.setItem('droply-sort', fSort); } catch {}
  loadFiles();
};
syncFilterUI();

// ---- меню файла: переименовать, переместить, удалить ----
const fm = $('#fileMenu'); let fmItem = null;
function openFileMenu(f) {
  fmItem = f; $('#fmName').textContent = f.name;
  $('#fmShare').hidden = false; $('#fmDl').hidden = !!f.dir;
  fm.showModal();
}
fm.addEventListener('click', e => { if (e.target === fm) fm.close(); });
$('#fmCancel').onclick = () => fm.close();
$('#fmShare').onclick = () => { fm.close(); openShare(rel(fmItem.name)); };
$('#fmDl').onclick = () => {
  fm.close();
  const a = el('a'); a.href = '/f/' + encodeURIComponent(fmItem.name) + (cwd ? '?dir=' + encodeURIComponent(cwd) : '');
  a.dataset.dl = fmItem.name; a.dataset.size = fmItem.size; document.body.append(a); a.click(); a.remove();
};
$('#fmRename').onclick = async () => {
  fm.close();
  const to = prompt('Новое имя', fmItem.name);
  if (!to || to === fmItem.name) return;
  const r = await api('POST', '/api/files/rename', JSON.stringify({ dir: cwd, name: fmItem.name, to }), jsonHdr);
  if (!r.ok) { toast((await r.text()).trim()); return; }
  toast('Переименовано'); loadFiles(); loadShares();
};
$('#fmDelete').onclick = async () => {
  fm.close(); const f = fmItem;
  if (!confirm(f.dir ? `Удалить папку «${f.name}» со всем содержимым?` : `Удалить «${f.name}»?`)) return;
  await api('DELETE', '/api/files/' + encodeURIComponent(f.name) + (cwd ? '?dir=' + encodeURIComponent(cwd) : ''));
  loadFiles(); loadShares();
};
const md = $('#moveDlg');
$('#fmMove').onclick = async () => {
  fm.close(); const f = fmItem, self = rel(f.name);
  const tree = await (await api('GET', '/api/tree')).json();
  const ul = $('#moveList'); ul.replaceChildren();
  $('#moveName').textContent = 'Переместить «' + f.name + '»';
  for (const d of [''].concat(tree.sort((a, b) => a.localeCompare(b, 'ru')))) {
    if (d === cwd) continue; // уже здесь
    if (f.dir && (d === self || d.startsWith(self + '/'))) continue; // в саму себя нельзя
    const li = el('li', 'clickable');
    const depth = d ? d.split('/').length : 0;
    const b = el('div', 'badge folder'); b.innerHTML = FOLDER;
    const info = el('div', 'info'); info.append(el('div', 'name', d ? d.split('/').pop() : 'Мои файлы'), el('div', 'meta', d ? '/' + d : 'корень'));
    li.style.marginLeft = Math.min(depth, 4) * 14 + 'px';
    li.append(b, info);
    li.onclick = async () => {
      const r = await api('POST', '/api/files/move', JSON.stringify({ dir: cwd, names: [f.name], to: d }), jsonHdr);
      const j = await r.json().catch(() => ({}));
      md.close();
      if (!r.ok || (j.failed && j.failed.length)) { toast(j.failed ? j.failed[0] : 'Не удалось переместить'); return; }
      toast('Перемещено в «' + (d || 'Мои файлы') + '»'); loadFiles(); loadShares();
    };
    ul.append(li);
  }
  $('#moveEmpty').hidden = ul.children.length > 0;
  md.showModal();
};
$('#moveCancel').onclick = () => md.close();
md.addEventListener('click', e => { if (e.target === md) md.close(); });

$('#askFiles').onclick = () => { addDlg.close(); openShare(cwd, 'in'); };

// ---- просмотр ----
const view = $('#view');
const VIEW = { img: /\.(jpe?g|png|gif|webp|heic|heif|bmp)$/i, vid: /\.(mp4|m4v|mov|webm)$/i, aud: /\.(mp3|m4a|aac|wav|ogg|flac)$/i, doc: /\.(pdf|txt|md|log)$/i };
let viewIdx = -1;
const mediaList = () => curFiles.filter(x => !x.dir && (VIEW.img.test(x.name) || VIEW.vid.test(x.name)));
function stepView(d) {
  const l = mediaList(); if (l.length < 2 || viewIdx < 0) return;
  viewIdx = (viewIdx + d + l.length) % l.length; openView(l[viewIdx], true);
}
function openView(f, stepping) {
  const q = cwd ? '?dir=' + encodeURIComponent(cwd) : '';
  viewIdx = mediaList().findIndex(x => x.name === f.name);
  const nav = viewIdx >= 0 && mediaList().length > 1;
  $('#viewPrev').hidden = $('#viewNext').hidden = !nav;
  $('#viewPos').textContent = nav ? `${viewIdx + 1} / ${mediaList().length}` : '';
  const src = '/f/' + encodeURIComponent(f.name) + (q ? q + '&' : '?') + 'inline=1';
  if (VIEW.doc.test(f.name)) { window.open(src, '_blank'); return; }
  const body = $('#viewBody'); body.replaceChildren();
  let m;
  if (VIEW.img.test(f.name)) { m = el('img'); m.alt = f.name; }
  else if (VIEW.vid.test(f.name)) { m = el('video'); m.controls = true; m.playsInline = true; m.preload = 'metadata'; }
  else if (VIEW.aud.test(f.name)) { m = el('audio'); m.controls = true; }
  if (m) {
    m.src = src;
    m.onerror = () => body.replaceChildren(el('p', 'muted', 'Этот формат браузер не показывает — скачайте файл.'));
    body.append(m);
  } else body.append(el('p', 'muted', 'Предпросмотр для этого типа файлов недоступен.'));
  $('#viewName').textContent = f.name;
  $('#viewDl').href = '/f/' + encodeURIComponent(f.name) + q; $('#viewDl').dataset.dl = f.name; $('#viewDl').dataset.size = f.size;
  $('#viewShare').onclick = () => { view.close(); openShare(rel(f.name)); };
  if (!stepping) view.showModal();
}
$('#viewPrev').onclick = () => stepView(-1);
$('#viewNext').onclick = () => stepView(1);
document.addEventListener('keydown', e => { if (!view.open) return; if (e.key === 'ArrowLeft') stepView(-1); if (e.key === 'ArrowRight') stepView(1); });
let tx = 0, ty = 0; // свайп влево/вправо — соседний файл
$('#viewBody').addEventListener('touchstart', e => { tx = e.touches[0].clientX; ty = e.touches[0].clientY; }, { passive: true });
$('#viewBody').addEventListener('touchend', e => {
  const dx = e.changedTouches[0].clientX - tx, dy = e.changedTouches[0].clientY - ty;
  if (Math.abs(dx) > 50 && Math.abs(dx) > Math.abs(dy) * 1.5) stepView(dx < 0 ? 1 : -1);
});
const closeView = () => { $('#viewBody').replaceChildren(); view.close(); };
$('#viewClose').onclick = closeView;
view.addEventListener('click', e => { if (e.target === view) closeView(); });
view.addEventListener('close', () => $('#viewBody').replaceChildren());

$('#newFolder').onclick = async () => {
  addDlg.close();
  const name = prompt('Название папки');
  if (!name || !name.trim()) return;
  const r = await api('POST', '/api/folders', JSON.stringify({ dir: cwd, name: name.trim() }), jsonHdr);
  if (!r.ok) { toast(await r.text()); return; }
  loadFiles();
};

async function loadShares() {
  const r = await api('GET', '/api/shares');
  const list = await r.json();
  $('#cntShares').textContent = list.length ? list.length + ' ' + plural(list.length, 'активная', 'активные', 'активных') : '';
  const ul = $('#shares'); ul.replaceChildren();
  $('#noshares').hidden = list.length > 0;
  for (const s of list) {
    const li = el('li');
    const info = el('div', 'info');
    const word = s.kind === 'in' ? 'добавлено' : 'скачано';
    const lim = s.max ? `${word} ${s.count}/${s.max}` : `${word} ${s.count}`;
    info.append(el('div', 'name', (s.pass ? '🔒 ' : '') + (s.kind === 'in' ? (s.shared ? '👥 Общая папка «' : '⬇ Приём в «') + (s.name || 'Мои файлы') + '»' : s.name)), el('div', 'meta', `${left(s.expires)} · ${lim}`));
    const acts = el('div', 'row-acts');
    const o = iconBtn('qr', 'Показать', 'acc'); o.onclick = () => showResult(s);
    const d = iconBtn('del', 'Отозвать', 'del');
    d.onclick = async () => { await api('DELETE', '/api/shares/' + s.token); toast('Ссылка отозвана'); loadShares(); };
    acts.append(o, d);
    let sb = badge(s.name);
    if (s.dir) { sb = el('div', 'badge folder'); sb.innerHTML = FOLDER; }
    li.append(sb, info, acts); ul.append(li);
  }
}

// ---- вкладки ----
document.querySelectorAll('.tab').forEach(t => t.onclick = () => {
  document.querySelectorAll('.tab').forEach(x => x.classList.toggle('active', x === t));
  $('#paneFiles').hidden = t.dataset.tab !== 'files';
  $('#paneShares').hidden = t.dataset.tab !== 'shares';
});

// ---- диалог ссылки ----
const dlg = $('#dlg');
let curName = '', curUrl = '', curKind = '';
document.querySelectorAll('.chips[data-name]').forEach(g => g.onclick = e => {
  if (e.target.tagName !== 'BUTTON') return;
  g.querySelectorAll('button').forEach(b => b.classList.toggle('on', b === e.target));
});
const chip = name => +document.querySelector(`.chips[data-name="${name}"] .on`).dataset.v;
function modeHint() {
  $('#modeHint').textContent = chip('mode') === 1
    ? 'По ссылке видно файлы папки: их можно скачать и добавить свои. Удалять может только владелец.'
    : 'По ссылке можно только прислать файлы — содержимое папки не видно.';
}
document.querySelector('.chips[data-name="mode"]').addEventListener('click', () => setTimeout(modeHint));
function openShare(name, kind) {
  curName = name; curKind = kind || '';
  $('#dlgName').textContent = curKind === 'in' ? 'Совместно: «' + (name ? name.split('/').pop() : 'Мои файлы') + '»' : name.split('/').pop();
  $('#maxLbl').textContent = curKind === 'in' ? 'Сколько файлов можно добавить' : 'Скачиваний';
  $('#modeBox').hidden = curKind !== 'in'; modeHint();
  const mb = document.querySelectorAll('.chips[data-name="max"] button');
  mb[1].textContent = curKind === 'in' ? '1 файл' : '1 раз'; mb[2].textContent = curKind === 'in' ? '5 файлов' : '5 раз';
  $('#shPass').value = '';
  $('#dlgForm').hidden = false; $('#dlgRes').hidden = true;
  dlg.showModal();
}
function showResult(s) {
  curName = s.name; curUrl = s.url;
  $('#dlgName').textContent = s.kind === 'in' ? (s.shared ? 'Общая папка «' : 'Приём в «') + (s.name || 'Мои файлы') + '»' : s.name;
  $('#url').value = s.url;
  $('#qr').src = '/api/shares/' + s.token + '/qr.svg';
  $('#share').hidden = !navigator.share;
  $('#dlgForm').hidden = true; $('#dlgRes').hidden = false;
  if (!dlg.open) dlg.showModal();
}
$('#cancel').onclick = $('#close').onclick = () => dlg.close();
dlg.addEventListener('click', e => { if (e.target === dlg) dlg.close(); });
$('#mk').onclick = async () => {
  const r = await api('POST', '/api/shares', JSON.stringify({ name: curName, hours: chip('hours'), max: chip('max'), kind: curKind, password: $('#shPass').value, shared: chip('mode') === 1 }), jsonHdr);
  if (!r.ok) { toast(await r.text()); return; }
  showResult(await r.json());
  loadShares();
};
$('#copy').onclick = async () => {
  copyText(curUrl, $('#copy'), $('#url'));
};
$('#share').onclick = () => navigator.share({ title: curName, url: curUrl }).catch(() => {});

// ---- выбор и перетаскивание ----
const pick = $('#pick');
pick.onchange = () => { runQueue([...pick.files]); pick.value = ''; };
// перетаскивание файла в любое место страницы (ПК)
document.addEventListener('dragover', e => { e.preventDefault(); document.body.classList.add('dragging'); });
document.addEventListener('dragleave', e => { if (!e.relatedTarget) document.body.classList.remove('dragging'); });
document.addEventListener('drop', e => { e.preventDefault(); document.body.classList.remove('dragging'); if (e.dataTransfer.files.length) runQueue([...e.dataTransfer.files]); });
// кнопка ＋
const addDlg = $('#addDlg');
$('#fab').onclick = () => addDlg.showModal();
$('#addCancel').onclick = () => addDlg.close();
addDlg.addEventListener('click', e => { if (e.target === addDlg) addDlg.close(); });
$('#addUpload').onclick = () => { addDlg.close(); pick.click(); };
$('#dockSearch').onclick = () => { document.querySelector('.dock .tab[data-tab="files"]').click(); const q = $('#q'); q.focus(); q.scrollIntoView({ block: 'center' }); };
$('#dockMe').onclick = () => $('#me').click();

// ---- аккаунт ----
const acc = $('#acc');
let me = null;
function accView(v) {
  $('#accMain').hidden = v !== 'main'; $('#pwForm').hidden = v !== 'pw'; $('#usersPane').hidden = v !== 'users'; $('#invPane').hidden = v !== 'inv';
}
$('#me').onclick = () => { accView('main'); acc.showModal(); };
acc.addEventListener('click', e => { if (e.target === acc) acc.close(); });
acc.querySelectorAll('.back').forEach(b => b.onclick = () => accView('main'));
$('#openPw').onclick = () => { $('#pwForm').reset(); accView('pw'); };
let invUrl = '';
$('#openInv').onclick = async () => {
  const r = await api('GET', '/api/invite'); if (!r.ok) { toast(await r.text()); return; }
  const j = await r.json(); invUrl = j.url;
  $('#invQr').src = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(j.qr);
  $('#invUrl').value = j.url;
  $('#invClosed').hidden = j.open;
  $('#invShare').hidden = !navigator.share;
  accView('inv');
};
$('#invCopy').onclick = async () => {
  copyText(invUrl, $('#invCopy'), $('#invUrl'));
};
$('#invShare').onclick = () => navigator.share({ title: 'Droply — регистрация', url: invUrl }).catch(() => {});
addEyes(document);
$('#logout').onclick = async () => { await api('POST', '/api/logout'); location.href = '/login.html'; };
$('#pwForm').onsubmit = async e => {
  e.preventDefault();
  const r = await api('POST', '/api/me/password', JSON.stringify({ old: $('#pwOld').value, new: $('#pwNew').value }), jsonHdr);
  if (!r.ok) { toast(await r.text()); return; }
  toast('Пароль изменён'); $('#pwWeak').hidden = true; me.weak_pw = false; accView('main');
};
$('#openUsers').onclick = () => { $('#userForm').reset(); loadUsers(); accView('users'); };
$('#regToggle').onchange = async e => {
  await api('POST', '/api/settings', JSON.stringify({ registration: e.target.checked }), jsonHdr);
  toast(e.target.checked ? 'Регистрация открыта' : 'Регистрация закрыта');
};
async function loadUsers() {
  api('GET', '/api/settings').then(r => r.json()).then(j => $('#regToggle').checked = j.registration);
  const r = await api('GET', '/api/users');
  const list = await r.json();
  const ul = $('#userList'); ul.replaceChildren();
  for (const u of list) {
    const li = el('li');
    const b = el('div', 'badge', u.name[0]);
    const info = el('div', 'info');
    info.append(el('div', 'name', u.name + (u.admin ? ' · админ' : '')), el('div', 'meta', `${fmt(u.used)} из ${fmt(u.quota)} · ${u.pending ? 'не завершил регистрацию' : (u.totp ? '2FA ✓' : 'ждёт 2FA')}${u.keep ? ' · ∞' : ''}${u.max_file_mb ? ' · файл до ' + fmt(u.max_file) : ''}${u.email ? ' · ' + u.email : ''}`));
    const edit = iconBtn('qr', 'Изменить'); edit.innerHTML = '✎';
    edit.onclick = () => { $('#uName').value = u.name; $('#uEmail').value = u.email || ''; $('#uAdmin').checked = u.admin; $('#uKeep').checked = !!u.keep; $('#uPw').value = ''; $('#uQuota').value = ''; $('#uMaxFile').value = u.max_file_mb || ''; $('#uPw').focus(); };
    const acts = el('div', 'row-acts'); acts.append(edit);
    if (u.totp) {
      const r2 = iconBtn('qr', 'Сбросить 2FA'); r2.innerHTML = '⟲';
      r2.onclick = async () => {
        if (!confirm(`Сбросить 2FA у ${u.name}? При следующем входе он подключит её заново.`)) return;
        await api('POST', '/api/users/' + encodeURIComponent(u.name) + '/reset2fa'); toast('2FA сброшена'); loadUsers();
      };
      acts.append(r2);
    }
    if (u.name !== me.name) {
      const d = iconBtn('del', 'Удалить', 'del');
      d.onclick = async () => {
        if (!confirm(`Удалить пользователя ${u.name} и все его файлы?`)) return;
        const r = await api('DELETE', '/api/users/' + encodeURIComponent(u.name));
        if (!r.ok) toast(await r.text()); else loadUsers();
      };
      acts.append(d);
    }
    li.append(b, info, acts); ul.append(li);
  }
}
$('#userForm').onsubmit = async e => {
  e.preventDefault();
  const body = { name: $('#uName').value, password: $('#uPw').value, email: $('#uEmail').value || '-', admin: $('#uAdmin').checked, keep: $('#uKeep').checked };
  if (+$('#uQuota').value > 0) body.quota_gb = +$('#uQuota').value;
  body.max_file_mb = Math.max(0, Math.round(+$('#uMaxFile').value || 0));
  const r = await api('POST', '/api/users', JSON.stringify(body), jsonHdr);
  if (!r.ok) { toast(await r.text()); return; }
  toast('Сохранено'); $('#userForm').reset(); loadUsers();
};
async function loadMe() {
  const r = await api('GET', '/api/me');
  me = await r.json();
  $('#me').textContent = me.name[0];
  $('#accName').textContent = me.name; hello(me.name);
  $('#openUsers').hidden = !me.admin;
  if (me.weak_pw && !acc.open) { // старый простой пароль — просим сменить
    $('#pwForm').reset(); $('#pwWeak').hidden = false; accView('pw'); acc.showModal();
  }
}

// ---- подсказка «установить как приложение» ----
const inst = $('#inst');
let deferredPrompt = null;
window.addEventListener('beforeinstallprompt', e => { e.preventDefault(); deferredPrompt = e; });
// В установленном приложении (iOS) переход по ссылке на файл открывает его на весь экран без кнопки «назад».
// Поэтому там: до 150 МБ — системное меню «Поделиться» (Сохранить видео / в Файлы), больше — отдельное окно Safari с кнопкой «Готово».
document.addEventListener('click', async e => {
  const a = e.target.closest('a[data-dl]');
  if (!a || !standalone()) return;
  e.preventDefault();
  const size = +a.dataset.size || 0;
  const canFiles = navigator.canShare && navigator.canShare({ files: [new File(['x'], 'x.txt', { type: 'text/plain' })] });
  if (size > 150 << 20 || !canFiles) { window.open(a.href, '_blank'); return; }
  // скачиваем, затем кнопка «Сохранить» — share() требует свежего нажатия
  const sd = $('#saveDlg');
  $('#saveName').textContent = a.dataset.dl; $('#saveState').textContent = 'Загрузка… 0%';
  $('#saveGo').disabled = true; sd.showModal();
  try {
    const r = await fetch(a.href, { credentials: 'same-origin' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const total = +r.headers.get('content-length') || size, rd = r.body.getReader(), parts = []; let got = 0;
    for (;;) {
      const { done, value } = await rd.read(); if (done) break;
      parts.push(value); got += value.length;
      if (!sd.open) { rd.cancel(); return; }
      $('#saveState').textContent = 'Загрузка… ' + Math.round(got / Math.max(total, 1) * 100) + '%';
    }
    const file = new File(parts, a.dataset.dl, { type: guessType(a.dataset.dl) });
    $('#saveState').textContent = 'Готово · ' + fmt(file.size);
    $('#saveGo').disabled = false;
    $('#saveGo').onclick = async () => { try { await navigator.share({ files: [file] }); } catch {} sd.close(); };
  } catch (err) { $('#saveState').textContent = 'Ошибка: ' + err.message; }
});
$('#saveCancel').onclick = () => $('#saveDlg').close();
function guessType(n) {
  const ext = (n.split('.').pop() || '').toLowerCase();
  return { jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', gif: 'image/gif', heic: 'image/heic', mp4: 'video/mp4', mov: 'video/quicktime', m4v: 'video/mp4', pdf: 'application/pdf', mp3: 'audio/mpeg', m4a: 'audio/mp4' }[ext] || 'application/octet-stream';
}
const standalone = () => matchMedia('(display-mode: standalone)').matches || navigator.standalone === true;
function platform() {
  const ua = navigator.userAgent;
  if (/iPhone|iPad|iPod/.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1)) return 'IOS';
  if (/Android/.test(ua)) return 'Android';
  return 'Desktop';
}
function showInstall() {
  const p = platform();
  ['IOS', 'Android', 'Desktop'].forEach(x => $('#inst' + x).hidden = x !== p);
  $('#instGo').textContent = deferredPrompt ? 'Установить' : 'Понятно';
  inst.showModal();
}
function store(k, v) { try { v === undefined ? localStorage.getItem(k) : localStorage.setItem(k, v); } catch (e) {} }
function stored(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
$('#instLater').onclick = () => { store('droply.inst', 'later'); inst.close(); };
$('#instGo').onclick = async () => {
  store('droply.inst', 'done');
  if (deferredPrompt) { deferredPrompt.prompt(); deferredPrompt = null; }
  inst.close();
};
inst.addEventListener('click', e => { if (e.target === inst) inst.close(); });
$('#openInst').onclick = () => { acc.close(); showInstall(); };
// подсказка об установке — только на телефонах; на ПК не всплывает (пункт в меню тоже скрыт)
if (!standalone() && platform() !== 'Desktop' && !stored('droply.inst')) setTimeout(showInstall, 800);
$('#openInst').hidden = standalone() || platform() === 'Desktop';

loadMe();
loadFiles();
loadShares();

// ---- push и колокольчик ----
let myEndpoint = '', pushKeyB64 = '';
const isIOS = /iP(hone|ad|od)/.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
const pushSupported = () => 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window;
function u8(b64) { const s = atob(b64.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((b64.length + 3) % 4)); return Uint8Array.from(s, c => c.charCodeAt(0)); }
async function pushState() {
  const b = $('#openPush'), bp = $('#bellPush');
  if (!pushSupported()) {
    b.hidden = !isIOS; b.textContent = 'Push: сначала установите на экран «Домой»'; bp.hidden = true; return;
  }
  b.hidden = false;
  const reg = await navigator.serviceWorker.ready;
  const sub = await reg.pushManager.getSubscription();
  myEndpoint = sub ? sub.endpoint : '';
  const on = !!sub && Notification.permission === 'granted';
  b.textContent = on ? 'Push на этом устройстве: включены' : (Notification.permission === 'denied' ? 'Push запрещены в настройках телефона' : 'Включить push-уведомления');
  bp.hidden = on || Notification.permission === 'denied';
}
async function pushToggle() {
  if (!pushSupported()) { acc.close(); showInstall(); return; }
  const reg = await navigator.serviceWorker.ready;
  const cur = await reg.pushManager.getSubscription();
  if (cur && Notification.permission === 'granted') {
    if (!confirm('Выключить push-уведомления на этом устройстве?')) return;
    await api('DELETE', '/api/push/sub', JSON.stringify({ endpoint: cur.endpoint }), jsonHdr).catch(() => {});
    await cur.unsubscribe().catch(() => {});
    toast('Push выключены'); pushState(); return;
  }
  const perm = await Notification.requestPermission(); // первым — пока жест пользователя «свежий» (iOS)
  if (perm !== 'granted') { toast('Уведомления не разрешены'); pushState(); return; }
  try {
    if (!pushKeyB64) pushKeyB64 = (await (await api('GET', '/api/push/key')).json()).key;
    const sub = cur || await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: u8(pushKeyB64) });
    const r = await api('POST', '/api/push/sub', JSON.stringify(sub.toJSON()), jsonHdr);
    if (!r.ok) throw new Error(await r.text());
    toast('Push включены — пришлю проверочное');
  } catch (e) { toast('Не удалось включить: ' + e.message); }
  pushState();
}
$('#openPush').onclick = pushToggle;
$('#bellPush').onclick = pushToggle;
if (pushSupported()) api('GET', '/api/push/key').then(r => r.json()).then(j => pushKeyB64 = j.key).catch(() => {});
pushState().catch(() => {});

const bellDlg = $('#bellDlg');
async function loadEvents(render) {
  const r = await api('GET', '/api/events'); const j = await r.json();
  const c = $('#bellCnt'); c.hidden = !j.unread; c.textContent = j.unread > 9 ? '9+' : j.unread;
  if (!render) return;
  const ul = $('#bellList'); ul.replaceChildren();
  $('#bellEmpty').hidden = j.items.length > 0;
  for (const e of j.items) {
    const li = el('li', e.t > j.seen ? 'new' : '');
    li.append(el('div', 'name', e.text), el('div', 'meta', ago(e.t)));
    ul.append(li);
  }
}
$('#bell').onclick = async () => {
  await loadEvents(true); bellDlg.showModal();
  api('POST', '/api/events/seen').then(() => { $('#bellCnt').hidden = true; }).catch(() => {});
};
$('#bellClose').onclick = () => bellDlg.close();
$('#bellClear').onclick = async () => {
  await api('DELETE', '/api/events');
  $('#bellList').replaceChildren(); $('#bellEmpty').hidden = false; $('#bellCnt').hidden = true;
  toast('Уведомления очищены');
};
bellDlg.addEventListener('click', e => { if (e.target === bellDlg) bellDlg.close(); });
loadEvents().catch(() => {});
setInterval(() => { if (!document.hidden) loadEvents().catch(() => {}); }, 60000);
document.addEventListener('visibilitychange', () => { if (!document.hidden) { loadEvents().catch(() => {}); loadFiles(); } });

// Android: «Поделиться» из других приложений -> service worker кладёт файлы в кэш и открывает /?shared=1
if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});
if (new URLSearchParams(location.search).has('shared')) (async () => {
  history.replaceState(null, '', '/');
  try {
    const c = await caches.open('droply-share');
    const mr = await c.match('/shared-meta'); if (!mr) return;
    const meta = await mr.json();
    const files = [];
    for (let i = 0; i < meta.n; i++) {
      const fr = await c.match('/shared-file-' + i); if (!fr) continue;
      files.push(new File([await fr.blob()], meta.names[i] || 'file', { type: fr.headers.get('content-type') || '' }));
    }
    await caches.delete('droply-share');
    if (files.length) runQueue(files);
  } catch (e) { toast('Не удалось принять файлы'); }
})();

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

// очистка поиска
$('#qx').onclick = () => { const q = $('#q'); q.value = ''; $('#qx').hidden = true; loadFiles(); q.focus(); };
