/*
 * Fora AI — Service Worker
 * Sits between the app and the network: caches static assets for instant
 * repeat loads, keeps recently-viewed pages available offline, and falls
 * back to a friendly offline screen when a page was never cached.
 *
 * Bump CACHE_VERSION whenever style.css / main.js / icons change so old
 * caches get cleaned up and users get the new files.
 */
const CACHE_VERSION = 'v1';
const STATIC_CACHE = `fora-static-${CACHE_VERSION}`;
const PAGE_CACHE = `fora-pages-${CACHE_VERSION}`;
const OFFLINE_URL = '/offline/';

// Core assets needed for the app shell + offline page to render with no network.
const PRECACHE_URLS = [
  '/offline/',
  '/static/css/style.css',
  '/static/js/main.js',
  '/static/manifest.json',
  '/static/icons/icon-192.png',
  '/static/icons/icon-512.png',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(STATIC_CACHE)
      .then((cache) => cache.addAll(PRECACHE_URLS))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys
          .filter((key) => key !== STATIC_CACHE && key !== PAGE_CACHE)
          .map((key) => caches.delete(key))
      )
    ).then(() => self.clients.claim())
  );
});

function isStaticAsset(url) {
  return url.pathname.startsWith('/static/');
}

self.addEventListener('fetch', (event) => {
  const { request } = event;

  // Only handle same-origin GET requests. POSTs (scan submissions, forms,
  // payments, webhooks) must always hit the network untouched.
  if (request.method !== 'GET') return;

  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;

  // Never intercept admin, auth, or payment/webhook flows — always fresh.
  if (
    url.pathname.startsWith('/foraoops') ||
    url.pathname.startsWith('/payments/') ||
    url.pathname.startsWith('/integrations/webhook/')
  ) {
    return;
  }

  // Static assets: cache-first, refresh in background (stale-while-revalidate).
  if (isStaticAsset(url)) {
    event.respondWith(
      caches.open(STATIC_CACHE).then((cache) =>
        cache.match(request).then((cached) => {
          const networkFetch = fetch(request)
            .then((response) => {
              if (response.ok) cache.put(request, response.clone());
              return response;
            })
            .catch(() => cached);
          return cached || networkFetch;
        })
      )
    );
    return;
  }

  // Page navigations: network-first, cache the result for offline reuse,
  // fall back to the cached copy, then to the offline page.
  if (request.mode === 'navigate') {
    event.respondWith(
      fetch(request)
        .then((response) => {
          if (response.ok) {
            const copy = response.clone();
            caches.open(PAGE_CACHE).then((cache) => cache.put(request, copy));
          }
          return response;
        })
        .catch(() =>
          caches.match(request).then((cached) => cached || caches.match(OFFLINE_URL))
        )
    );
  }
});

// ---------- Push notifications (scaffold) ----------
// Requires a backend endpoint to store push subscriptions and a service
// (e.g. web-push + VAPID keys) to actually send pushes — not wired up yet.
// Safe to leave in place; it just won't fire until that backend exists.
self.addEventListener('push', (event) => {
  if (!event.data) return;
  let payload = {};
  try {
    payload = event.data.json();
  } catch (e) {
    payload = { title: 'Fora AI', body: event.data.text() };
  }
  event.waitUntil(
    self.registration.showNotification(payload.title || 'Fora AI', {
      body: payload.body || 'You have a new update.',
      icon: '/static/icons/icon-192.png',
      badge: '/static/icons/icon-192.png',
      data: { url: payload.url || '/dashboard/' },
    })
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const targetUrl = event.notification.data?.url || '/dashboard/';
  event.waitUntil(
    self.clients.matchAll({ type: 'window' }).then((clientsList) => {
      for (const client of clientsList) {
        if (client.url.includes(targetUrl) && 'focus' in client) return client.focus();
      }
      if (self.clients.openWindow) return self.clients.openWindow(targetUrl);
    })
  );
});
