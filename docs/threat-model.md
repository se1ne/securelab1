# Модель загроз SecureLab, ЛР 6

Рівень: відмінний. Автор: Лімаз Федір Сергійович, КБ-41.

| Елемент | Що зафіксовано |
|---|---|
| Версія та середовище | Review-start: `c4563b23b81be981138eed86ebafca8ea47fc94a` (кінець ЛР 5; тег `v0.5.0` = `985120699e456ae0541b88aa1c457aad68be193d`, після нього додано лише docs). .NET SDK 10.0.302. Профіль запуску: Development (`launchSettings.json`), БД PostgreSQL 127.0.0.1:54329, seed/reset через `--reset-database`, пароль seed-акаунтів із `SeedUsers__Password` поза Git. |
| Компоненти в межах огляду | Браузерний клієнт (`Client/*`: index, browser-lab, auth-lab), API (ASP.NET Core minimal API), PostgreSQL (Docker Compose), конфігурація (`appsettings*.json`, `infra/.env.example`, змінні середовища), журнали (`ILogger`: diagnostic і `Audit`). Redis не використовується. |
| Активи | Облікові дані (парольні хеші Identity, cookie сеансу); власні інциденти й коментарі (конфіденційність, цілісність); внутрішні коментарі Analyst; переходи статусу (triage) лише для Analyst; журнали аудиту й безпеки; секрети конфігурації (connection string, seed-пароль). |
| Суб'єкти | Анонімний відвідувач; Reporter (Alice, Bob); Analyst (Morgan); Administrator (admin: не має доступу до list/search/summary); локальний розробник з доступом до репозиторію й БД. |
| Entry points | `GET /api/incidents`, `GET /api/incidents/{id}`, `GET /api/incidents/severity-summary`, `GET /api/incidents/search`, `POST /api/incidents`, `PUT /api/incidents/{id}`, `DELETE /api/incidents/{id}`, `POST /api/incidents/{id}/triage`, `GET /api/incident-comments/{id}`, `POST /api/auth/register`, `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/me`, `GET /api/auth/session-check`, `GET /health`; форми `browser-lab.html`, `auth-lab.html`; завантаження конфігурації; restore NuGet; журнали. |
| Межі довіри | browser→API; API→PostgreSQL; repository→build; environment→configuration. |
| Наявні controls | Authentication: cookie (`HttpOnly`, `SameSite=Lax`, `Secure` поза Development), `RequireAuthorization()` на захищених маршрутах (ЛР 3). Authorization: роль і власник у запиті БД, однакова 404 для чужого й неіснуючого запису (ЛР 4, матриця A-*). Validation: server-side для create/update (ЛР 2). XSS: safe DOM, `createTextElement` (ЛР 5, REG-XSS-01). CORS: точний origin лише Development (REG-CORS-01). CSP `default-src 'self'; frame-ancestors 'none'`, `nosniff`, `no-referrer`. Rate limiting: `login` (10 запитів за 2 с). Журнал входу з `traceId`. |
| Виключення | Production-інфраструктура й HTTPS-термінація; сторонні пакети поза `dotnet package list --vulnerable`; історія Git поза явно переглянутими файлами; `/scalar` (лише Development); інші браузери, окрім Firefox. |

## Схема меж довіри

```
[Браузер: Client/*] --(1) HTTP + cookie--> [API ASP.NET Core] --(2) Npgsql--> [PostgreSQL]
                                                  ^   |
[Репозиторій + NuGet] --(3) restore/build-----+   +--> [ILogger: diagnostic + Audit]
[Змінні середовища, appsettings] --(4) configuration--+
```

## Очікувані властивості на межах

| Межа | Очікувана властивість | Конкретний test або перевірка |
|---|---|---|
| browser→API | Мутація, що змінює стан, виконується лише з валідним antiforgery-токеном; відповідь не виконується як код; доступ лише за роллю й власником; перебір відмов блокується | REG-CSRF-01 (login → без токена відмова → стан не змінено → токен → успіх → стан змінено); REG-XSS-01; A-* матриця; REG-DENY-01 (advanced variant) |
| API→PostgreSQL | Запити параметризовані; власник у `Where`; помилка БД не віддає деталей клієнту | тести ЛР 2 (search), ЛР 4 (IDOR); безпечна 500 з `traceId` без деталей (етап 2) |
| repository→build | Відомі вразливі пакети відсутні або прийняті з причиною; lock-файли зафіксовані | `dotnet package list --vulnerable --include-transitive`, `packages.lock.json` |
| environment→configuration | Секрети не в Git; Production не використовує Development-значення | пошук секретів у відстежуваних файлах (`docs/evidence/secrets-review.md`); `.gitignore`; тест на відсутність Development-налаштувань у Production-like запуску |

## Актив → загроза → control → перевірка

| Актив | Загроза | Control | Перевірка |
|---|---|---|---|
| Запис інциденту іншого користувача | IDOR: читання, зміна, видалення чужого запису | Власник у `Where`; однакова 404 | Матриця A-*; REG-DENY-01 (відмови фіксуються) |
| Облікові дані | Підбір пароля, enumeration | Rate limit `login`; однаковий результат для невідомого користувача й невірного пароля | `LoginRateLimitTests`, A07_UnknownUserAndWrongPassword |
| Cookie сеансу | CSRF-мутація від імені користувача | Antiforgery (етап 2) | REG-CSRF-01 |
| Дані на сторінці | Stored XSS | safe DOM, CSP | REG-XSS-01, DOM-тести |
| Журнали аудиту | Втрата доказів, витік секретів у лог | Окрема категорія `Audit`, без паролів і cookie | Читання через in-memory `ILoggerProvider`; перегляд логів шести сценаріїв |
| Секрети конфігурації | Витік через Git | `.gitignore`, пароль seed з env | `docs/evidence/secrets-review.md` |
| Доступність API | Перебір відмов, brute force | Блокування на 5 відмов за 60 с; rate limiting | REG-DENY-01; `SearchRateLimitTests`, `LoginRateLimitTests` |

## Стан після ЛР 6

Нові controls (усі перевірені тестами або ручними доказами в `docs/security-review.md`):

| Control | Що закриває | Перевірка |
|---|---|---|
| Antiforgery для мутацій (header `X-CSRF-TOKEN`, token прив'язаний до користувача) | CSRF через cookie-сеанс | REG-CSRF-01, периметр PUT/DELETE/triage/create/logout |
| Rate limit `search` (20 за 10 с на користувача) | Навантаження й перебір через пошук | `SearchRateLimitTests` |
| Audit відмов доступу, burst на 5-й відмові, 429 до кінця вікна | Перебір чужих id, розвідка меж доступу | REG-DENY-01 (`AuthorizationDenialBurstTests`) |
| Audit triage (`incident.triaged`) | Непрозорі привілейовані зміни (F-03) | REG-AUDIT-01 |
| Відбиток замість введеного імені при невдалому вході | Витік випадково введених паролів у журнал (F-01) | REG-LOG-01 |
| HTTPS-редирект і HSTS поза Development | Перехоплення першого запиту по http (F-02) | REG-HTTPS-01 |
| Перевірка CORS і заголовків | Чужий origin, MIME sniffing, ембедінг | REG-CORS-01, REG-HDR-01 |

## Залишкові ризики

| Ризик | Чому прийнято | Що зменшує |
|---|---|---|
| Login CSRF: форма входу не захищена antiforgery | До входу немає cookie й токен неможливо одержати; зміна сеансу жертви без втрати даних | `SameSite=Lax`, rate limit `login` |
| Лічильники відмов у пам'яті одного екземпляра | Немає спільного сховища; при кількох екземплярах поріг множиться | Короткий життєвий цикл вікна, вилучення старих partition |
| Немає блокування акаунта після невдалих входів (`lockoutOnFailure:false`) | Блокування дозволяє зловмиснику заблокувати чужий акаунт | Limiter `login` за IP (10 за 2 с); спільний NAT ділить квоту |
| Реєстрація розкриває існування імені/email (409) і не має ліміту | Типова навчальна поведінка | Не розв'язано в ЛР 6 |
| Cookie сеансу має стандартний строк Identity (14 днів, sliding) | Не змінювалося в межах ЛР 6 | `HttpOnly`, `Secure`, `SameSite` |
| CSP без `base-uri` і `form-action` | Ці директиви не наслідують `default-src`; на сторінках немає динамічного HTML | `default-src 'self'`, `frame-ancestors 'none'`, safe DOM |
| Журнали лише в консоль процесу | Немає централізованого сховища й захисту від зміни | Окрема категорія `Audit`, без паролів і cookie |
| HTTPS-порт редиректу зафіксовано як 443; HSTS preload не вмикався | Припущення про reverse proxy | Налаштування `Security:EnforceHttps` |
