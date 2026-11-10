# Регресійний пакет ЛР 6

Останній повний запуск: `dotnet test`, 2026-11-10, **85 тестів з 85 пройдено**, 0 помилок. Тести запускаються з локальним `SeedUsers__Password` поза Git.

| ID | Що захищає | Тести | Результат |
|---|---|---|---|
| REG-AUTHN | Вхід, вихід, `/api/me`, однаковий результат для невідомого й хибного пароля, підроблений id ігнорується | `AuthenticationMechanicsTests` (10) | пройдено |
| REG-COOKIE | Прапорці cookie (`HttpOnly`, `Secure`, `SameSite`) | `CookieFlagsTests` | пройдено |
| REG-AUTHZ | Матриця доступу LR4: anonymous 401, чужий запис 404, роль 403, власні дані у list/search/summary, внутрішні коментарі | `IncidentEndpointTests` (30) | пройдено |
| REG-INPUT | Валідація, дублікат, межі, overposting, пошук | `Lab02RegressionTests` (6), `SearchMechanicsTests` | пройдено |
| REG-XSS-01 | Клієнтський код без небезпечного `innerHTML` | `IncidentEndpointTests.ClientScript_DoesNotUseDangerousInnerHtmlSink` | пройдено |
| REG-HASH | Перехешування паролів | `PasswordHasherUpgradeTests` | пройдено |
| REG-CSRF-01 | Мутація без токена відхиляється й не змінює стан; з токеном проходить; периметр PUT/DELETE/triage/create/logout | `CsrfRegressionTests` (6) | пройдено |
| REG-RATE-LOGIN | Limiter входу: 429 після квоти і відновлення | `LoginRateLimitTests` | пройдено |
| REG-RATE-SEARCH | Limiter пошуку: квота на користувача, ізоляція Alice/Bob, відновлення | `SearchRateLimitTests` | пройдено |
| REG-DENY-01 | Advanced variant: audit кожної відмови (матриця з 9 випадків), burst на 5-й, одне повідомлення на вікно, 429 з `Retry-After` і окремим типом, мутація під 429 не змінює стан, logout доступний, скидання після вікна (fake `TimeProvider`), вилучення partition, потокобезпечність | `AuthorizationDenialBurstTests` (17 з урахуванням теорії) | пройдено |
| REG-AUDIT-01 | F-03: успішний triage лишає запис аудиту, 403 і 409 його не створюють | `TriageAuditTests` | пройдено |
| REG-LOG-01 | F-01: журнал входу без введеного імені й паролів | `LoginLoggingTests` (5) | пройдено |
| REG-HTTPS-01 | F-02: редирект на HTTPS і HSTS при увімкненому режимі | `HttpsEnforcementTests` (3) | пройдено |
| REG-CORS-01 | Чужий origin не отримує дозволів CORS (запит і preflight) | `CorsAndHeadersTests.REG_CORS_01_*` | пройдено |
| REG-HDR-01 | CSP, `nosniff`, `no-referrer` у відповідях API | `CorsAndHeadersTests.REG_HDR_01_*` | пройдено |

Ручні перевірки (скріншоти в звіті): безпечна 500 із `traceId` у Production-like режимі, відсутність секретів у журналах (grep), блокування й відновлення після 5 відмов, блокування вбудованого скрипта політикою CSP.
