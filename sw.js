// JMOS Service Worker — Offline Caching
const CACHE_NAME = 'jmos-v1';
const CACHE_URLS = [
  '/',
  '/WV_OEE_App.html',
  '/manifest.json'
];

// Install — cache the app shell
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      console.log('[SW] Caching app shell');
      return cache.addAll(CACHE_URLS);
    })
  );
  self.skipWaiting();
});

// Activate — clean up old caches
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

// Fetch — network first for API, cache first for app shell
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  // API calls — always go to network (never cache)
  if (url.pathname.startsWith('/api/')) {
    return;
  }

  // App shell — network first, fall back to cache
  event.respondWith(
    fetch(event.request)
      .then(response => {
        // Update cache with fresh version
        if (response.ok) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
        }
        return response;
      })
      .catch(() => {
        // Offline — serve from cache
        return caches.match(event.request).then(cached => {
          if (cached) return cached;
          // If requesting the root, serve the cached HTML
          if (url.pathname === '/' || url.pathname === '') {
            return caches.match('/WV_OEE_App.html');
          }
          return new Response('Offline', { status: 503, statusText: 'Offline' });
        });
      })
  );
});

// Listen for sync events (background sync when back online)
self.addEventListener('message', event => {
  if (event.data === 'skipWaiting') {
    self.skipWaiting();
  }
});
