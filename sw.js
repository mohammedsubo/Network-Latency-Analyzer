// sw.js - Simple Service Worker
const CACHE_NAME = 'network-analyzer-v2';
const urlsToCache = [
  '/',
  '/index.html',
  '/src/style-enhanced.css',
  '/src/main-enhanced.js'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(urlsToCache))
  );
});

self.addEventListener('fetch', event => {
  event.respondWith(
    caches.match(event.request)
      .then(response => response || fetch(event.request))
  );
});
