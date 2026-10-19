# Звіт до лабораторної роботи № 3

## 1. Ідентифікація стану

- Тема: «Автентифікація та безпечна робота з обліковими даними».
- Базовий стан: завершена лабораторна робота № 2, тег `v0.2.0`.
- Базовий commit `v0.2.0`: `454fe220fe673999124182682d66807e3ae16b40`.
- Гілка: `lab/3-authentication`.
- Release ID scaffold: `lab-03-start-v1`.
- Scaffold/start commit: `b7379f58764137ef021e70c4c976d5a83e57d8d4`.
- Register / CP-01 commit: `9ff8366f9514f1a7b998d4abebd200bf0eb09787`.
- Фінальний commit: `85ae0aae12dbf926a0bcecc2c9da1362f203f70a8`.
- Фінальний тег: `v0.3.0`.
- Фінальний результат автоматичних тестів: `24/24`.

## 2. Основні виконані зміни

1. Встановлено scaffold ЛР 3 поверх завершеного стану `v0.2.0`.
2. Підключено та перевірено ASP.NET Core Identity з `ApplicationUser : IdentityUser<Guid>` та EF Core stores.
3. Перевірено два послідовні reset цикли зі стабільним seed-станом та успішним запуском тестів.
4. Завершено `POST /api/auth/register` із request DTO `RegistrationInput`.
5. Реалізовано server-side validation для `userName`, `email`, `displayName` та наявності `password`.
6. Текстові поля `userName`, `email` та `displayName` нормалізуються через `Trim()`, тоді як password навмисно не змінюється.
7. Для email застосовано базову перевірку формату через `MailAddress`.
8. Створення користувача виконується стандартним `UserManager.CreateAsync`, який перевіряє Identity rules, password policy, виконує password hashing та зберігає користувача.
9. Для duplicate username/email визначено послідовний контракт `409 Conflict`.
10. Додано окремий `RegistrationResponse`, який не повертає password, password hash або службові Identity-поля.
11. Реалізовано захищений `GET /api/me`, який визначає поточного користувача лише через verified `HttpContext.User`.
12. Усунуто небезпечну довіру до `X-Demo-UserId`: підроблений header більше не змінює поточного користувача.
13. Реалізовано logout через стандартний `SignInManager.SignOutAsync()`.
14. Перевірено фактичні cookie flags `HttpOnly`, `Secure` та `SameSite=Lax` у HTTPS test-сценарії без виведення значення cookie.
15. Для login збережено однаковий зовнішній результат `401 Unauthorized` як для невідомого користувача, так і для неправильного пароля.
16. Додано rate limiting лише до `POST /api/auth/login`: 10 спроб за 2 секунди, після чого повертається `429 Too Many Requests`.
17. Partition key для rate limit обрано за IP-адресою клієнта.
18. Додано мінімальні auth events для login без password, cookie, password hash, token, raw Authorization header або request body.
19. `POST /api/incidents` захищено через `.RequireAuthorization()`.
20. `Incident.OwnerUserId` більше не задається через hard-coded Alice, а визначається сервером з `ClaimTypes.NameIdentifier` authenticated principal.
21. Поле `ownerUserId`, передане клієнтом у JSON, не входить до `CreateIncidentRequest` і не може підмінити фактичного власника.
22. Старі regression-тести ЛР 2 для `POST /api/incidents` переведено на authenticated cookie client без зміни їх функціонального контракту.
23. Автоматизовано сценарії A-01–A-07.
24. Реалізовано browser flow: anonymous → login → profile → create → logout.
25. Проведено S-01 leak review відповідей API, логів, тестів, browser evidence та Git diff.
26. Для відмінного рівня виконано threat analysis login flow.
27. Для відмінного рівня продемонстровано готовність стандартного Identity password hasher до посилення параметрів через `SuccessRehashNeeded`.
28. Після фінального reset усі 24 автоматизовані тести завершилися успішно.

## 3. Контрольні точки

### CP-01. Register та безпечне зберігання password

Для реєстрації використовується окремий request DTO `RegistrationInput`:

- `UserName`;
- `Email`;
- `DisplayName`;
- `Password`.

Перед створенням користувача сервер виконує перевірки обов’язковості, довжини та формату полів. `UserName`, `Email` і `DisplayName` нормалізуються через `Trim()`, але password не нормалізується, щоб сервер не змінював секрет користувача.

Маршрут обробки:

`JSON → RegistrationInput → server-side validation → UserManager.CreateAsync → Identity store → RegistrationResponse`

Password hashing не реалізовується вручну. `UserManager<ApplicationUser>` використовує стандартний Identity password hasher і зберігає лише `PasswordHash`.

Response DTO містить тільки дозволені поля:

- `Id`;
- `UserName`;
- `DisplayName`.

Під час перевірки підтверджено:

- T-01: коректна реєстрація → `201 Created`;
- T-02: повторна реєстрація того самого username/email → `409 Conflict`;
- `displayName` довжиною 121 символ → `400 Bad Request`;
- response не містить `password` та `passwordHash`;
- у структурі `identity_users` немає поля для відкритого password, присутній лише `PasswordHash`, значення якого у звіт не виводилося;
- duplicate-contract автоматизовано regression-тестом.

CP-01 зафіксовано commit:

`9ff8366f9514f1a7b998d4abebd200bf0eb09787`

### CP-02. Verified principal у `/api/me`

Початковий scaffold містив навмисно небезпечну довіру до `X-Demo-UserId`. Клієнт міг передати довільний Guid у header, а endpoint використовував його для визначення профілю.

Після виправлення поточний користувач визначається лише через:

`authentication cookie → authentication middleware → HttpContext.User → ClaimTypes.NameIdentifier`

`GET /api/me` захищено через `.RequireAuthorization()`.

Під час перевірки підтверджено:

- A-01: анонімний `GET /api/me` → `401 Unauthorized`;
- A-02: після login Alice `/api/me` повертає дозволені profile fields Alice;
- A-03: cookie Alice + `X-Demo-UserId` Bob не змінює principal, відповідь залишається Alice;
- response `/api/me` не містить password або password hash;
- A-06: після logout повторний `/api/me` → `401`;
- A-07: невідомий користувач і неправильний password мають однаковий зовнішній результат.

Таким чином клієнтський UserId не входить до ланцюжка довіри.

### CP-03. Захищене створення інциденту та server-managed owner

`POST /api/incidents` захищено через `.RequireAuthorization()`.

Поточний owner визначається сервером:

`HttpContext.User → ClaimTypes.NameIdentifier → Guid ownerUserId → Incident.OwnerUserId`

`CreateIncidentRequest` не містить:

- `OwnerUserId`;
- `Id`;
- `Status`;
- `CreatedAtUtc`;
- `Role`.

Під час перевірки підтверджено:

- анонімний POST до захищеної операції → `401`;
- A-04: Bob створює інцидент без owner у DTO, у БД `OwnerUserId == DbSeeder.BobId`;
- A-05: Bob надсилає у JSON підроблений `ownerUserId = AliceId`, але створений запис все одно має owner Bob;
- старі regression-сценарії ЛР 2 на `201`, `400` і `409` продовжують працювати через authenticated client.

Це підтверджує, що hidden field, header або довільне поле JSON не є access control і не можуть замінити verified principal.

## 4. Таблиця перевірок

| ID | Сценарій | Передумови | Дія | Очікувано | Фактично | Доказ |
|---|---|---|---|---|---|---|
| T-01 | Коректна реєстрація | Унікальні username/email, коректний password | `POST /api/auth/register` | `201 Created`, safe response DTO | Отримано `201`, повернено `id`, `userName`, `displayName` | Рисунок 20 |
| T-02 | Duplicate registration | Користувача вже створено | Повторний register | `409 Conflict` | Отримано `409 Conflict` | Рисунок 21 |
| T-03 | Збережене представлення password | Identity schema створена | Перегляд структури `identity_users` без dump даних | Відсутній відкритий password, є `PasswordHash` | Підтверджено структуру без виведення hash | Рисунок 31 |
| A-01 | Anonymous → protected endpoint | Немає authentication cookie | `GET /api/me` | `401`, не redirect | Отримано `401 Unauthorized` | Рисунок 37 |
| A-02 | Login → `/api/me` | Seed account Alice | Login, потім `GET /api/me` | Профіль поточного principal | Повернуто Alice, sensitive fields відсутні | Рисунок 38 |
| A-03 | Forged `X-Demo-UserId` | Valid cookie Alice | `/api/me` з header Bob | Principal не змінюється | Повернуто Alice | Рисунок 39 |
| A-04 | Authenticated create без owner | Valid cookie Bob | `POST /api/incidents` без owner | Owner береться з principal | У БД owner = Bob | Рисунок 58 |
| A-05 | Forged owner у JSON | Valid cookie Bob | POST з `ownerUserId = AliceId` | Forged field не впливає на owner | У БД owner = Bob, не Alice | Рисунок 59 |
| A-06 | Logout → protected endpoint | Успішний login | Logout, потім `/api/me` | `204`, потім `401` | Отримано `204` і повторний `401` | Рисунок 40 |
| A-07 | Account enumeration resistance | Однаковий формат login request | Unknown user та wrong password | Однаковий зовнішній результат | Обидва випадки мають `401` і однакові стабільні поля error contract | Рисунок 41 |
| S-01 | Перевірка витоку | Після завершення реалізації | Review response/log/tests/diff | Немає secret values | Password/hash/cookie/token/connection string у доказах не виявлено | Рисунки 72–73 |

## 5. Cookie authentication і межа довіри

Фіксований профіль cookie:

- `HttpOnly = true`;
- `SameSite = Lax`;
- `SecurePolicy = SameAsRequest` у Development;
- `SecurePolicy = Always` поза Development.

Фактичний test виконував login через HTTPS base address і перевіряв лише атрибути `Set-Cookie`, не виводячи значення authentication cookie.

Підтверджено:

- `HttpOnly`;
- `Secure`;
- `SameSite=Lax`.

`HttpOnly` зменшує можливість читання cookie звичайним JavaScript. `Secure` обмежує передачу cookie HTTPS-з’єднанням. `SameSite=Lax` обмежує частину cross-site надсилань.

Ці прапорці не є повною CSRF-моделлю. State-changing cookie-authenticated endpoint-и до реалізації окремого CSRF-захисту залишають навчальний CSRF debt.

Verified маршрут:

`Login request → Identity password verification → authentication cookie → browser sends cookie → authentication handler → HttpContext.User → NameIdentifier → current user / resource owner`

## 6. Rate limiting та auth events

До `POST /api/auth/login` застосовано окрему named policy `login`.

Параметри:

- partition key: IP-адреса клієнта;
- `PermitLimit = 10`;
- `Window = 2 seconds`;
- `QueueLimit = 0`;
- відхилений запит → `429 Too Many Requests`.

IP-адресу обрано як partition key, тому що username як ключ дозволив би атакуючому навмисно витрачати quota конкретного акаунта. Password не може використовуватися як partition key, оскільки є credential.

Обмеження IP-based підходу:

- користувачі за спільним NAT ділять один ліміт;
- розподілений атакуючий може використовувати різні IP;
- in-memory limiter є локальним навчальним механізмом і не є повним distributed rate limiting solution.

Автоматичний тест підтвердив:

1. перші 10 дозволених login attempts доходять до authentication і повертають `401` для тестового unknown user;
2. 11-й запит повертає `429`;
3. після завершення вікна login знову доходить до authentication і повертає `401`.

Auth event містить лише:

- event type;
- username;
- result;
- trace identifier.

Навмисно виключено:

- password;
- cookie;
- password hash;
- token;
- raw Authorization header;
- request body.

## 7. Browser flow

Для browser flow було завершено `auth-lab.html` та `auth-lab.js`.

Підтверджено п’ять спостережень:

1. До login `/api/me` повертає `401`, UI показує анонімний стан.
2. Після login Alice сервер повертає `204`, після чого `/api/me` показує лише дозволені profile fields Alice.
3. Browser create request містить `title`, `description`, `severity`, `occurredAtUtc` і не містить `OwnerUserId`; `POST /api/incidents` повертає `201`.
4. Після logout сервер повертає `204`, а повторний `/api/me` повертає `401`.
5. Код не записує credentials або principal у `localStorage`, `sessionStorage`, dataset DOM чи Console.

Для fetch використовується `credentials: "same-origin"`. JavaScript не читає authentication cookie; її автоматично обробляє браузер.

## 8. S-01 — перевірка витоку

Після завершення реалізації виконано review:

- API responses;
- application logs;
- automated tests;
- browser evidence;
- Git diff.

Додатково виконано пошук за словами, пов’язаними із secret artifacts.

Допустимими є лише назви полів і перевірки, наприклад `PasswordHash` у DTO-check. Фактичні значення password hash не виводилися.

За результатами S-01 у доказах не виявлено:

- реального password;
- значення `PasswordHash`;
- authentication cookie value;
- token;
- raw Authorization header;
- connection string із credentials;
- request body із password.

Auth events містять тільки контрольовані несекретні поля.

## 9. Поглиблення для відмінного рівня

### 9.1. Threat analysis login flow

Основні активи:

- password користувача;
- authentication cookie;
- verified identity у `HttpContext.User`.

Основний entry point:

`POST /api/auth/login`

Trust boundary проходить між недовіреними даними клієнта та даними, які сервер вважає verified після перевірки ASP.NET Core Identity.

Реалістична загроза:

- масовий перебір credentials;
- account enumeration.

Контрзаходи:

- однаковий `401 Unauthorized` для unknown user і wrong password;
- rate limit із `429 Too Many Requests`;
- auth events без credentials;
- cookie flags;
- використання стандартного Identity password verification.

Residual risk:

- in-memory rate limiter не є distributed protection;
- IP-based partition може зачепити користувачів за спільним NAT;
- атакуючий може розподіляти спроби між різними IP;
- `SameSite=Lax` не є повною CSRF-моделлю.

### 9.2. Готовність стандартного password hasher до оновлення

Окремим test-only сценарієм створено два стандартних `PasswordHasher<ApplicationUser>`:

- старіший варіант із меншою кількістю iterations;
- сильніший варіант із більшою кількістю iterations.

Password хешується старішим стандартним hasher, після чого stronger hasher виконує `VerifyHashedPassword`.

Очікуваний і фактичний результат:

`PasswordVerificationResult.SuccessRehashNeeded`

Це означає:

- password перевірено успішно;
- старий hash залишається сумісним;
- поточні параметри вважаються слабшими;
- Identity може зберегти оновлений hash після успішної перевірки.

Власна криптографія не реалізовувалася, значення hash у test output або звіт не виводилося.

## 10. Автоматичні тести

Після завершення всіх змін виконано:

`dotnet test tests/SecureLab.Api.Tests -c Release`

Фактичний фінальний результат:

`Test summary: total: 24, failed: 0, succeeded: 24, skipped: 0`

Перед фінальним запуском база була повернута до seed-стану.

Автоматизовані перевірки включають:

- збережені regression tests попередніх лабораторних;
- duplicate registration;
- A-01;
- A-02;
- A-03;
- A-04;
- A-05;
- A-06;
- A-07;
- cookie flags;
- login rate limit та recovery;
- password hasher upgrade readiness;
- старі create validation / conflict regression-сценарії через authenticated client;
- cleanup створених test resources.

## 11. Git-історія

Базовий стан ЛР 2:

`454fe220fe673999124182682d66807e3ae16b40` (`v0.2.0`)

Scaffold/start commit:

`b7379f58764137ef021e70c4c976d5a83e57d8d4`

Register / CP-01 commit:

`9ff8366f9514f1a7b998d4abebd200bf0eb09787`

Фінальний перевірений commit:

`85ae0aae12dbf926a0bcecc2c9da1362f203f70a8`

Фінальний annotated tag:

`v0.3.0`

Перед створенням фінального commit було виконано reset, build та повний набір тестів. Після цього commit і tag було відправлено до remote repository.

Окремі commit-и саме для CP-02 і CP-03 не створювалися; їх реалізація та перевірки входять до фінального commit `85ae0aae12dbf926a0bcecc2c9da1362f203f70a8`.

## 12. Декларація використання генеративного ШІ

Під час виконання лабораторної роботи використовувався сервіс генеративного ШІ.

Основні задачі використання:

- пояснення вимог методичних рекомендацій;

- пояснення ASP.NET Core Identity, cookie authentication та verified principal;
- допомога з побудовою register validation і safe response DTO;
- пояснення trust boundary для `/api/me` та `OwnerUserId`;
- допомога зі сценаріями A-01–A-07;

Згенеровані рекомендації та код не використовувалися без перевірки. Вони адаптувалися до фактичної структури проєкту та перевірялися через build, integration tests, ручні HTTP-сценарії та browser flow.

Після завершення роботи всі 24 автоматизовані тести пройшли успішно.

## 13. Висновок

У лабораторній роботі було реалізовано автентифікацію користувачів та безпечну роботу з обліковими даними за допомогою ASP.NET Core Identity, EF Core та cookie authentication.

Було завершено register boundary із server-side validation, safe response DTO, послідовним duplicate-contract та стандартним password hashing. Реалізовано `/api/me`, який визначає користувача тільки з verified principal, а також стандартний logout.

Перевірено фактичні cookie flags, реалізовано login rate limiting та безпечні auth events без credentials. Захищено `POST /api/incidents`, а `OwnerUserId` тепер визначається сервером з `ClaimTypes.NameIdentifier`; підроблений клієнтом `ownerUserId` не може змінити фактичного власника ресурсу.

Автоматизовано A-01–A-07, збережено regression-перевірки попередньої лабораторної, виконано повний browser flow та S-01 leak review.

Для відмінного рівня проведено threat analysis login flow і продемонстровано можливість стандартного Identity hasher розпізнавати hash зі старішими параметрами через `SuccessRehashNeeded`.

Після фінального reset весь набір із 24 автоматизованих тестів завершився успішно. Фінальний стан збережено в гілці `lab/3-authentication` та позначено тегом `v0.3.0`.
