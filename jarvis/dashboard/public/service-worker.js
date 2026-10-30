const CACHE = 'jarvis-mobile-v1';

self.addEventListener('install', event => {
  event.waitUntil(caches.open(CACHE).then(cache => cache.addAll(['/mobile', '/manifest.webmanifest', '/jarvis-icon.svg'])));
  self.skipWaiting();
});

self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));

self.addEventListener('fetch', event => {
  const request = event.request;
  const url = new URL(request.url);
  if (request.method !== 'GET' || url.origin !== self.location.origin || url.pathname.startsWith('/api/')) return;
  event.respondWith(fetch(request).then(response => {
    if (response.ok) void caches.open(CACHE).then(cache => cache.put(request, response.clone()));
    return response;
  }).catch(() => caches.match(request).then(cached => cached || caches.match('/mobile'))));
});
