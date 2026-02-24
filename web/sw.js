const CACHE_NAME = "incomudon-pwa-v42";
const CACHE_PREFIX = "incomudon-pwa-";
const swURL = new URL(self.location.href);
const authMode = String(swURL.searchParams.get("auth_mode") || "none").toLowerCase();
const authEnabled = authMode !== "none";
const APP_SHELL = [
  "./",
  "./index.html",
  "./styles.css",
  "./app.js",
  "./worklets/mic-capture-worklet.js",
  "./worklets/pcm-playback-worklet.js",
  "./manifest.webmanifest",
  "./icon.svg",
  "./locales/en.json",
  "./locales/ja.json",
  "./sfx/ptt_on.wav",
  "./sfx/ptt_off.wav",
  "./sfx/carrier_sense.wav",
];

self.addEventListener("install", (event) => {
  if (!authEnabled) {
    event.waitUntil(
      caches.open(CACHE_NAME).then((cache) => cache.addAll(APP_SHELL)),
    );
  }
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  const shouldDelete = authEnabled
    ? (key) => key.startsWith(CACHE_PREFIX)
    : (key) => key !== CACHE_NAME;

  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys
          .filter((key) => shouldDelete(key))
          .map((key) => caches.delete(key)),
      ),
    ),
  );
  self.clients.claim();
});

self.addEventListener("fetch", (event) => {
  if (event.request.method !== "GET") {
    return;
  }

  const requestURL = new URL(event.request.url);
  if (requestURL.origin !== self.location.origin) {
    return;
  }

  if (authEnabled) {
    event.respondWith(
      fetch(event.request, { cache: "no-store" }),
    );
    return;
  }

  event.respondWith(
    caches.match(event.request).then((cached) => {
      if (cached) {
        return cached;
      }

      return fetch(event.request)
        .then((response) => {
          if (!response || response.status !== 200 || response.type !== "basic") {
            return response;
          }

          const clone = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
          return response;
        })
        .catch(() => caches.match("./index.html"));
    }),
  );
});
