# Security review SecureLab, ЛР 6

Рівень: відмінний («Відмінно»). Commit початку огляду (review-start): `c4563b23b81be981138eed86ebafca8ea47fc94a` (кінець ЛР 5). Хеші прийнятого merge commit і тегу `v1.0.0` додає скрипт експорту в PDF. Дата: 2026-11-10. SDK: .NET 10.0.302. Профіль: Development і Production-like (`ASPNETCORE_ENVIRONMENT=Production`, `--no-launch-profile -c Release`). Клієнт: Firefox 159 (DevTools), `curl.exe`, автотести xUnit.

## 1. Executive summary

Перевірено межі browser→API, API→PostgreSQL, repository→build, environment→configuration для варіанта 2-A (трекер інцидентів). Реальних секретів у відстежуваних файлах немає. Зафіксовано й виправлено три власні знахідки: F-01 (журнал входу записував введене ім'я), F-02 (немає редиректу на HTTPS і HSTS поза Development), F-03 (успішний triage не лишав запису аудиту). Додано antiforgery для всіх cookie-мутацій, rate limit пошуку, audit відмов доступу з блокуванням на 5-й відмові (advanced variant). Повний регресійний пакет проходить: 85 тестів з 85 на гілці `lab/6-hardening-review`. Результат прогону на прийнятому merge commit додає скрипт експорту. Головні залишкові ризики: login CSRF, лічильники відмов лише в пам'яті одного екземпляра, відсутність блокування акаунта, enumeration при реєстрації.

## 2. Scope та exclusions

Перевірено поточні відстежувані файли Git, код API, клієнт `Client/*`, конфігурацію, журнали, залежності. Історія Git: лише пошук рядка `local-study-password` (`git log --all -S`), решта історії не перевірялася. Не входять: production-інфраструктура й HTTPS-термінація, `/scalar` (лише Development), інші браузери, окрім Firefox, вміст сторонніх пакетів поза перевіркою відомих вразливостей. Докладно: `docs/threat-model.md`.

## 3. System overview і trust boundaries

Схема й таблиця очікуваних властивостей на межах: `docs/threat-model.md`. Зв'язок «актив → загроза → control → перевірка» для ключових активів:

| Актив | Загроза | Control | Перевірка |
|---|---|---|---|
| Чужі інциденти | IDOR: читання, зміна, видалення | Власник у `Where`; однакова 404 для чужого й неіснуючого запису | `IncidentEndpointTests` (A01–A07), REG-DENY-01 |
| Стан інциденту (зміна, triage) | CSRF від імені користувача | Antiforgery (header `X-CSRF-TOKEN`, token прив'язаний до користувача) | REG-CSRF-01, периметр PUT/DELETE/triage/create/logout |
| Привілейований перехід (triage) | Непрозора зміна без слідів (F-03) | Audit-запис `incident.triaged` | REG-AUDIT-01 |
| Облікові дані й журнали | Витік введеного тексту в журнал (F-01) | Відбиток замість введеного імені при невдачі | REG-LOG-01 |
| Транспорт сеансу | Перехоплення першого http-запиту (F-02) | HTTPS-редирект і HSTS | REG-HTTPS-01 |
| Доступність пошуку | Навантаження через `search` | Limiter `search` (20 за 10 с на користувача) | `SearchRateLimitTests` |
| Межі доступу | Перебір чужих id | Audit відмов, burst на 5-й відмові, 429 до кінця вікна | REG-DENY-01 |
| Секрети конфігурації | Витік через Git | `.gitignore`, пароль seed поза Git | `docs/evidence/secrets-review.md` |

## 4. Methodology та test environment

Початковий стан: гілка `lab/6-hardening-review` від `c4563b2`; база PostgreSQL у Docker Compose (127.0.0.1:54329); дані скидалися командою `$env:Database__AllowReset="true"; dotnet run --project src/SecureLab.Api -- --reset-database` (потрібен `SeedUsers__Password` поза Git). Облікові записи seed: alice, bob (Reporter), morgan (Analyst), admin. Кінцевий commit для огляду: `40ff796` (потім merge і тег; їхні хеші додає експорт). Команди: `dotnet build`, `dotnet test` (код завершення 0, 85 з 85), `dotnet package list --vulnerable --include-transitive`, `dotnet package list --deprecated`, `git grep`, `curl.exe`, консоль браузера. Клієнт і сеанс названо в кожній картці finding.

## 5. Findings summary

| ID | Актив | Вплив | Ймовірність | Пріоритет | Статус | Повторна перевірка |
|---|---|---|---|---|---|---|
| F-03 | Привілейований перехід triage, дані аудиту | Середній: неможливо розслідувати зміну статусу | Висока (кожен triage) | P2 | Fixed | REG-AUDIT-01 |
| F-01 | Журнали, облікові дані | Низький: введений текст у журналі | Середня | P3 | Fixed | REG-LOG-01 |
| F-02 | Транспорт сеансу | Низький: перший запит по http | Низька (cookie має `Secure`) | P3 | Fixed | REG-HTTPS-01 |

Обґрунтування пріоритетів: F-03 вищий, бо дія привілейована й повторювана, а відсутність запису блокує розслідування будь-якої зміни. F-01 і F-02 зменшують ризик, але прямий витік обмежений (F-01 потребує помилкового введення, F-02 стримується `Secure`-cookie). CVSS не вигадувався.

## 6. Detailed findings

- `docs/findings/F-01-login-log-raw-username.md`
- `docs/findings/F-02-no-https-enforcement.md`
- `docs/findings/F-03-triage-not-audited.md`

F-03 виявлено власним аналізом журналів (сценарій привілейованого переходу). Дефекти журналювання й транспорту не називаються прямо в рядках checklist етапу 2, тому вважаються знайденими поза прямим checklist.

## 7. Regression results

Останній повний запуск на гілці: `dotnet test`, 2026-11-10, 85 з 85, код завершення 0. Результат прогону на прийнятому merge commit додає експорт PDF.

| ID | Тест або команда | Передумова | Результат | Стан ресурсу |
|---|---|---|---|---|
| SQLi | `Lab02RegressionTests.S02_ControlInput_DoesNotExpandResultSet`, `SearchMechanicsTests` | Seed-дані, вхід alice | Пройдено: керуючі символи не розширюють вибірку; значення параметрів SQL у журналі маскуються `'?'` | Дані не змінюються |
| Authentication | `AuthenticationMechanicsTests` (10), `CookieFlagsTests` | Seed-дані | Пройдено: anonymous 401, однаковий результат для невідомого й хибного пароля, прапорці cookie, logout | Сеанс закінчується після logout |
| Authorization / IDOR | `IncidentEndpointTests` (A01–A07, 30 тестів) | Alice, Bob, Morgan, admin | Пройдено: чужий запис 404, роль 403, власні дані у list/search/summary | Чужі записи не змінюються |
| XSS | `IncidentEndpointTests.ClientScript_DoesNotUseDangerousInnerHtmlSink` | Клієнтський код | Пройдено | Не застосовується |
| REG-CSRF-01 | `CsrfRegressionTests.REG_CSRF_01_*` | Вхід alice, створений інцидент | Пройдено: PUT без токена 400 (`.../problems/antiforgery`), стан незмінний, із токеном 200, стан змінений | Перевірено читанням до й після |
| CSRF периметр | `CsrfRegressionTests.Perimeter_*` (PUT, DELETE, TRIAGE, CREATE, LOGOUT) | Cookie без токена | Пройдено: 400 і стан незмінний | Перевірено |
| Validation | `Lab02RegressionTests` (6), `Update_InvalidSeverity_Returns400` | Seed-дані | Пройдено | Стан незмінний при 400 |
| CORS (REG-CORS-01) | `CorsAndHeadersTests.REG_CORS_01_*`, `curl.exe` з `Origin: https://evil.example` | Анонімний клієнт | Пройдено: немає `Access-Control-Allow-*` для запиту й preflight | Не застосовується |
| Headers (REG-HDR-01) | `CorsAndHeadersTests.REG_HDR_01_*`, `curl.exe` | Анонімний клієнт | Пройдено: CSP, nosniff, no-referrer | Не застосовується |
| CSP | Консоль `auth-lab.html`: вставка inline-скрипта | Вхід у браузері | Inline-скрипт заблоковано, клієнт працює | Не застосовується |
| Login limiter | `LoginRateLimitTests`, консоль: 12 запитів | Різні partition | Пройдено: 10×401, далі 429, відновлення після вікна | Не застосовується |
| Search limiter | `SearchRateLimitTests`, консоль: 25 запитів | Alice і Bob | Пройдено: 20×200, 429, ізоляція partition, відновлення | Не застосовується |
| REG-DENY-01 | `AuthorizationDenialBurstTests` (17) | Fake `TimeProvider`, in-memory журнал | Пройдено: audit кожної відмови, burst один раз за вікно, 429 з `Retry-After`, мутація під 429 не змінює стан, logout доступний | Перевірено читанням після вікна |
| REG-AUDIT-01 | `TriageAuditTests` | Alice створює, Morgan робить triage | Пройдено | Статус змінюється один раз |
| REG-LOG-01 | `LoginLoggingTests` (5) | Невідоме ім'я, існуюче ім'я, пароль у полі імені | Пройдено: журнал без введеного імені й паролів | Не застосовується |
| REG-HTTPS-01 | `HttpsEnforcementTests` (3) | Режим `Security:EnforceHttps` | Пройдено: http→307, HSTS на https, Development без редиректу | Не застосовується |

## 8. Hardening controls

Профіль і клієнт для всіх рядків нижче: Development, Firefox 159 або `curl.exe`, якщо не сказано інше.

| Control | Ризик | Фактична перевірка | Межа |
|---|---|---|---|
| Antiforgery на cookie-мутаціях | CSRF | REG-CSRF-01; у браузері без токена 400 | Login/register поза периметром (рішення нижче) |
| Заголовки `nosniff`, `no-referrer`, CSP `default-src 'self'; frame-ancestors 'none'` | MIME sniffing, ембедінг, XSS | `curl.exe` для API і `auth-lab.html`, status 401/200 | CSP без `base-uri` і `form-action` |
| CORS лише Development, точний origin | Чужий origin | `curl.exe` з `Origin: https://evil.example`: 401, потім preflight 204 без `Allow-*` | У Production CORS вимкнено |
| Search limiter | Навантаження | 20×200, далі 429, Alice і Bob окремо, відновлення | Fixed window; пам'ять процесу |
| Login limiter | Підбір пароля | 10×401, далі 429, відновлення після паузи | Ключ — IP (у Development `X-Test-Partition`) |
| Audit відмов і burst | Перебір id | REG-DENY-01; консоль: 5×404, 6-й 429 `Retry-After: 60`, через 60 с знову 404 | Пам'ять одного екземпляра |
| HTTPS і HSTS (F-02) | Перехоплення першого запиту | Production-like: `curl` по http → 307 на `https://localhost/api/incidents` | HTTPS-порт 443, HSTS preload не вмикався |

**Різниці Development і Production-like** (Production-like перевірено на `curl.exe`): у Production `/openapi/v1.json` повертає 404, `/scalar/v1` лише повертає клієнтський HTML (SPA fallback), `--reset-database` відхиляється (`InvalidOperationException`), cookie `Secure` завжди, непередбачена помилка дає безпечну 500 з `traceId`, HTTPS-редирект і HSTS увімкнені за замовчуванням. У Development: OpenAPI/Scalar доступні, reset дозволено, `Secure` як у запиті, CORS-політика лише для лабораторного origin, редирект вимкнено.

**Advanced variant (а): виявлення перебору відмов.** Погоджено з викладачем (`docs/evidence/advanced-variant-agreement.md`) до реалізації. Один фільтр `AuthorizationDenialFilter` на маршрутах ЛР 4 і create пише audit відмови (403/404): subject, action, resource, result, time, traceId. П'ята відмова одного користувача за 60 с дає подію `authorization.denied.burst` (один раз за вікно), далі запити цього користувача отримують 429 `authorization-denied-burst` з `Retry-After`. Умови викладача: для list/search/summary відмова лише за роллю; 404 для неіснуючого id рахується як відмова (ЛР 4 повертає однакову 404); logout доступний під час блокування; 429 відрізняється від 429 limiter пошуку; мутація під 429 не змінює стан; burst один раз за вікно; вікно фіксоване; fake `TimeProvider` без нових пакетів; лічильник потокобезпечний, прострочені partition вилучаються.

**Периметр cookie-мутацій:**

| ID | Method + route | Джерело / розбіжність | Яка зміна стану | Cookie authentication | Browser-accessible | Antiforgery validation | Regression ID |
|---|---|---|---|---|---|---|---|
| SC-01 | POST `/api/incidents` | ЛР 2, client call (`browser-lab.js`, `auth-lab.js`) | Створення інциденту | так | так | explicit | REG-CSRF-01 (CREATE) |
| SC-02 | PUT `/api/incidents/{id}` | ЛР 4 | Зміна змісту | так | так | explicit | REG-CSRF-01 |
| SC-03 | DELETE `/api/incidents/{id}` | ЛР 4 | Видалення | так | так | explicit | периметр DELETE |
| SC-04 | POST `/api/incidents/{id}/triage` | ЛР 4 | Статус New → Triaged | так | так | explicit | периметр TRIAGE, REG-AUDIT-01 |
| SC-05 | POST `/api/auth/logout` | ЛР 3 | Завершення сеансу | так | так | explicit (до `SignOutAsync`) | периметр LOGOUT |
| SC-06 | POST `/api/auth/login`, `/api/auth/register` | ЛР 3 | Створення сеансу / облікового запису | ні | так | absent: рішення нижче | `LoginRateLimitTests`, `AuthenticationMechanicsTests` |

Рішення щодо login і register: cookie автентифікації ще немає, а токен, прив'язаний до користувача, неможливо одержати до входу, тому antiforgery не застосовується. Login CSRF — залишковий ризик; зменшує limiter `login` і `SameSite=Lax`.

## 9. Dependency and secret audit

**Секрети:** `docs/evidence/secrets-review.md` (класифікація кожного збігу `git grep`, `.gitignore`, перевірка журналів). Реальних секретів немає; три входження синтетичного `local-study-password` прийнято для локальної навчальної БД.

**Залежності** (`dotnet package list`, SDK 10.0.302, джерело nuget.org):

| Перевірка | Результат | Рішення |
|---|---|---|
| `--vulnerable --include-transitive` | У SecureLab.Api і SecureLab.Api.Tests вразливих пакетів немає | Дій не потрібно |
| `--deprecated`, SecureLab.Api | Застарілих немає | Дій не потрібно |
| `--deprecated`, SecureLab.Api.Tests | `xunit` 2.9.3 позначено Legacy (альтернатива `xunit.v3`) | Тимчасово прийнято: пакет лише в тестовому проєкті, не потрапляє в API, advisory немає. Міграція на `xunit.v3` змінює harness і виходить за межі ЛР 6 |

**Систематичний пошук у відстежуваних файлах:** `git grep -n -iE "password|secret|apikey|token|connectionstring"` по `src` і `tests`, кожен збіг класифіковано в `secrets-review.md`. Історія Git: див. розділ 2.

## 10. Residual risks

| Ризик | Відповідальний | Наступна дія |
|---|---|---|
| Login CSRF (форма входу без antiforgery) | Автор | Оцінити pre-session token або `SameSite=Strict` для cookie входу |
| Лічильники відмов лише в пам'яті одного екземпляра | Автор | За потреби спільне сховище з TTL (напр. Redis) |
| Немає блокування акаунта після невдалих входів (`lockoutOnFailure:false`) | Автор | Оцінити тимчасове блокування з урахуванням DoS на чужий акаунт |
| Реєстрація розкриває існування імені/email (409) і не має ліміту | Автор | Додати limiter і нейтральну відповідь |
| Cookie сеансу з типовим строком Identity (14 днів, sliding) | Автор | Скоротити строк і задати абсолютний ліміт |
| CSP без `base-uri` і `form-action` | Автор | Додати директиви й перевірити клієнт |
| Журнали лише в консоль процесу | Автор | Централізоване сховище й захист від зміни |
| HTTPS-порт редиректу зафіксовано як 443; HSTS preload не вмикався | Автор | Налаштувати під фактичне розгортання |
| `xunit` 2.9.3 Legacy у тестовому проєкті | Автор | Перейти на `xunit.v3` окремою зміною |

## 11. Conclusion

Усі три знайдені дефекти виправлені й закриті регресійними тестами; повний пакет з 85 тестів проходить на гілці роботи. Реальних секретів у відстежуваних файлах не знайдено. Перевірка охоплює межі огляду з розділу 2: історія Git, production-інфраструктура й чужі пакети поза межами перевірки. Відомі обмеження перелічено в розділі 10 як прийняті ризики. Результат прогону на прийнятому merge commit додає експорт PDF.

## 12. Evidence appendix

**Зв'язок відповіді з журналом (traceId).** Production-like, недоступна БД: `POST /api/auth/login` повертає безпечну 500 з `traceId` `00-db23bb9f…`. У журналі за тим самим `TraceId` (`db23bb9f…`) є записи запиту з `RequestPath: /api/auth/login`. Без stack trace, SQL, connection string і шляхів у відповіді.

**Шість сценаріїв журналу (етап 3, п. 4).**

| Сценарій | Що видно в журналі | Результат |
|---|---|---|
| Успішний вхід | `Authentication event login: user alice, result success, trace …` | Є запис без пароля |
| Невдалий вхід | До F-01: `user nobody-user-123, result failure`. Після: `userRef sha256:70803aed, result failure` | Прогалину усунено (F-01) |
| Відмова доступу | `Audit authorization.denied: subject …, action GET /api/incidents/{id:guid}, resource …, result not-found, time …, traceId …` і `Security event authorization.denied.burst` | Є запис |
| Помилка валідації | Нових рядків немає; відповідь 400 Problem Details без стека, SQL, шляхів | За задумом (подія клієнта) |
| Неочікувана помилка | Безпечна 500 з `traceId`, діагностика в журналі | Є зв'язок за `TraceId` |
| Привілейований перехід | До F-03: лише SQL `UPDATE incidents SET status`. Після: `Audit incident.triaged: subject …, resource …, result success …` | Прогалину усунено (F-03) |

**Відсутність чутливих даних у журналах.** У журналі Production-like запуску зі сценарієм неочікуваної помилки пошук `Select-String` за значенням `SeedUsers__Password`, паролем із запиту (`NotARealPassword1!`) і `cookie:|set-cookie` дав 0 збігів у кожному випадку. Для решти сценаріїв перевірено рядки журналу візуально й автотестами: `AuthorizationDenialBurstTests` і `LoginLoggingTests` стверджують, що записи не містять пароля та введеного імені. Значення параметрів SQL EF Core маскує як `'?'`. Токен і cookie на скріншотах закриті.

**Відтворення retest іншою людиною.** Скинути дані командою з розділу 4; задати локальний `SeedUsers__Password` поза Git; виконати `dotnet test` (очікується 85 з 85); для ручної перевірки запустити API і повторити кроки з розділу «Відтворення» відповідної картки F-xx.

## Декларація й журнал ШІ

Використовував(ла): так. Нижче чорнетка зі складу виконаних робіт.

| Дата | Завдання/фрагмент | Авторська адаптація | Перевірка й результат |
|---|---|---|---|---|
| листопад 2026 | Чернетки threat-model і secrets-review, структура finding cards | Автор виконав усі команди пошуку, переглянув збіги, вирішив, які знахідки брати | Результати команд звірено зі скріншотами |

ШІ використовувався здебільшому для пояснення завдань методички, розмежування рівнів виконання та пояснення коду. Також чорнетки для документів були відтворені за допомогою ШІ.
