'use strict';
// Публичная страница «Отправить файлы»: загрузка кусками в папку владельца ссылки.
(() => {
  const $ = s => document.querySelector(s);
  const q = $('#queue'), token = q.dataset.token, max = +q.dataset.max, CHUNK = 8 << 20;
  const H = { 'X-Landrop': '1' };
  const fmt = n => { const u = ['Б', 'КБ', 'МБ', 'ГБ']; let i = 0; while (n >= 1024 && i < 3) { n /= 1024; i++; } return (i ? n.toFixed(1) : n) + ' ' + u[i]; };
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  const base = '/s/' + encodeURIComponent(token) + '/up';
  function put(url, blob, onp) {
    return new Promise((res, rej) => {
      const x = new XMLHttpRequest(); x.open('PUT', url); x.setRequestHeader('X-Landrop', '1');
      x.upload.onprogress = e => onp(e.loaded);
      x.onload = () => { let j = {}; try { j = JSON.parse(x.responseText); } catch {} res({ status: x.status, ok: x.status < 300, j, text: x.responseText }); };
      x.onerror = () => rej(new Error('сеть')); x.send(blob);
    });
  }
  async function init(f) {
    const r = await fetch(base, { method: 'POST', headers: Object.assign({ 'Content-Type': 'application/json' }, H), body: JSON.stringify({ name: f.name, size: f.size }) });
    if (!r.ok) throw Object.assign(new Error((await r.text()).trim()), { fatal: true });
    return r.json();
  }
  async function upload(f) {
    const li = el('li'), info = el('div', 'info'), meta = el('div', 'meta', 'подготовка…'), bar = el('div', 'bar'), fill = el('i');
    bar.append(fill); info.append(el('div', 'name', f.name), meta, bar); li.append(info); q.prepend(li);
    try {
      if (f.size > max) throw new Error('больше лимита ' + fmt(max));
      let { id, offset, done } = await init(f), fails = 0;
      while (!done) {
        try {
          const b0 = offset;
          const r = await put(`${base}/${id}?offset=${offset}`, f.slice(offset, Math.min(offset + CHUNK, f.size)), n => {
            fill.style.width = ((b0 + n) / f.size * 100).toFixed(1) + '%'; meta.textContent = `${fmt(b0 + n)} из ${fmt(f.size)}`;
          });
          if (r.ok || r.status === 409) { offset = r.j.offset ?? offset; done = !!r.j.done; fails = 0; }
          else if (r.status >= 500) throw new Error('HTTP ' + r.status);
          else throw Object.assign(new Error(r.text.trim() || 'HTTP ' + r.status), { fatal: true });
        } catch (e) {
          if (e.fatal || ++fails > 20) throw e;
          meta.textContent = 'нет связи, повтор…'; await sleep(Math.min(2000 * fails, 15000));
          ({ offset } = await init(f).catch(() => ({ offset })));
        }
      }
      fill.style.width = '100%'; meta.textContent = 'отправлено · ' + fmt(f.size); meta.classList.add('okc');
    } catch (e) { meta.textContent = 'ошибка: ' + e.message; meta.classList.add('err'); bar.remove(); }
  }
  async function run(files) {
    for (const f of files) await upload(f);
    if (q.dataset.shared === 'true') setTimeout(() => location.reload(), 1200); // показать новые файлы в списке
  }
  const pick = $('#pick'), drop = $('#drop');
  pick.onchange = () => { run([...pick.files]); pick.value = ''; };
  ['dragenter', 'dragover'].forEach(v => drop.addEventListener(v, e => { e.preventDefault(); drop.classList.add('over'); }));
  ['dragleave', 'drop'].forEach(v => drop.addEventListener(v, e => { e.preventDefault(); drop.classList.remove('over'); }));
  drop.addEventListener('drop', e => run([...e.dataTransfer.files]));
})();
