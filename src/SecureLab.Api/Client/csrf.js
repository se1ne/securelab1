// Helper antiforgery для сторінок клієнта (ЛР 6).
// Токен лежить лише в пам'яті сторінки: F5 або перехід створює нову пам'ять.
// Cookie в JS storage не копіюється; токен не логуємо.
(function () {
  let cached = null;

  async function getToken() {
    if (cached) return cached;
    const response = await fetch("/api/auth/csrf-token", {
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    });
    if (!response.ok) {
      throw new Error(`CSRF token: HTTP ${response.status}`);
    }
    cached = await response.json();
    return cached;
  }

  // Після login/logout користувач змінюється: токен треба одержати знову.
  function clear() {
    cached = null;
  }

  // Для POST/PUT/PATCH/DELETE додає header з токеном. Повторно запит після 4xx не надсилається.
  async function csrfFetch(path, options = {}) {
    const method = (options.method || "GET").toUpperCase();
    if (method === "GET" || method === "HEAD" || method === "OPTIONS") {
      return fetch(path, options);
    }
    const token = await getToken();
    return fetch(path, {
      ...options,
      credentials: "same-origin",
      headers: { ...options.headers, [token.headerName]: token.token },
    });
  }

  window.csrf = { fetch: csrfFetch, clear };
})();
