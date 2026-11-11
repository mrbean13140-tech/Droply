'use strict';
// Приём «Поделиться» на Android и push-уведомления. Остальные запросы не трогаем (без кэша — всегда свежая версия).
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', e => {
  const u = new URL(e.request.url);
  if (e.request.method !== 'POST' || u.pathname !== '/share-target') return;
  e.respondWith((async () => {
    const fd = await e.request.formData();
    const files = fd.getAll('files').filter(f => typeof f === 'object' && f.size !== undefined);
    await caches.delete('droply-share');
    const c = await caches.open('droply-share');
    for (let i = 0; i < files.length; i++)
      await c.put('/shared-file-' + i, new Response(files[i], { headers: { 'content-type': files[i].type || 'application/octet-stream' } }));
    await c.put('/shared-meta', new Response(JSON.stringify({ n: files.length, names: files.map(f => f.name) })));
    return Response.redirect('/?shared=1', 303);
  })());
});

self.addEventListener('push', e => {
  let d = {};
  try { d = e.data.json(); } catch { d = { title: 'Droply', body: e.data ? e.data.text() : '' }; }
  e.waitUntil(self.registration.showNotification(d.title || 'Droply', {
    body: d.body || '', icon: '/icon-192.png?v=4', badge: '/icon-192.png?v=4', tag: d.tag, data: { url: d.url || '/' },
  }));
});
self.addEventListener('notificationclick', e => {
  e.notification.close();
  const url = new URL((e.notification.data && e.notification.data.url) || '/', self.location.origin).href;
  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
    for (const c of list) if ('focus' in c) { if (c.navigate) c.navigate(url).catch(() => {}); return c.focus(); }
    return self.clients.openWindow(url);
  }));
});
