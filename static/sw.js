const CACHE_NAME = "netwatch-e6-v6";
const STATIC_ASSETS = [
  "/",
  "/static/style.css?v=6",
  "/static/app.js?v=6",
  "/static/manifest.json",
  "/static/icon.svg"
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(STATIC_ASSETS))
  );
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k))
      )
    )
  );
  self.clients.claim();
});

self.addEventListener("fetch", (event) => {
  if (event.request.method !== "GET") return;

  const reqUrl = new URL(event.request.url);
  // NUNCA armazenar nem responder rotas /api/* via cache do Service Worker (sempre network-only)
  if (reqUrl.pathname.startsWith("/api/") || event.request.url.includes("/api/")) {
    event.respondWith(fetch(event.request, { cache: "no-store" }));
    return;
  }

  // Para assets estáticos, prioriza rede e atualiza cache, usando cache apenas se offline
  event.respondWith(
    fetch(event.request, { cache: "no-cache" })
      .then((networkResp) => {
        if (networkResp && networkResp.status === 200) {
          const respClone = networkResp.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(event.request, respClone));
        }
        return networkResp;
      })
      .catch(() => caches.match(event.request))
  );
});
