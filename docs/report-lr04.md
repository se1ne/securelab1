# Звіт до лабораторної роботи № 4

**Тема:** Авторизація, ролі, володіння ресурсом та IDOR/BOLA
**Виконав:** Лімаз Федір Сергійович, КБ-41
**Варіант:** baseline 2-A «Трекер інцидентів»
**Рівень виконання:** відмінний (з незавершеними пунктами — див. розділ 8)

## 1. Ідентифікація стану

- Гілка: `lab/4-authorization` (створена від тегу `v0.3.0`, commit `85ae0aa`).
- Vulnerable commit: `88880157c36107b7d2b30e61d75a30a592b54e73` (код авторизації ще не змінювався; commit містить матрицю доступу).
- Fixed commit (основний finding, details): `beb496d83d26edfb5e33ca524e08f8a63598e70a`.
- Проміжні commits:

| Крок | Commit |
|---|---|
| Update | `dcec5ce80a36af646e2242b9ba4fd6f644bf3c63` |
| Delete + ізоляція rate-limit у тестах | `546f688c78e90871166ad0fc8e9a53952dc8610c` |
| Triage | `e44a0368001677f66b975fed694be463ac2fc1af` |
| Internal comment | `cee6004182e12d019284d6d8e431d4c6c8857963` |
| A-11 (search, severity-summary) | `b9794f7e1be61d58d22c08cd5494e194f168e15a` |
| Додатковий дефект (дублікат `title`) | `b109c5c7d02299dd52ccecc6c019e9276fe2bbc4` |

- Фінальний перевірений commit для тегу: `b109c5c7d02299dd52ccecc6c019e9276fe2bbc4`.
- Фінальний тег: `v0.4.0` — **ще не поставлено** (див. розділ 9).
- Виправлення стану ЛР 3: не потрібне. Стартові перевірки пройшли (рис. 1–6).

## 2. Стартова перевірка

- Тег `v0.3.0` є; гілку створено командою `git switch -c lab/4-authorization v0.3.0` (рис. 1).
- Postgres: `Up`, `healthy` (рис. 3); reset виконано (рис. 4).
- Базовий набір: 25 тестів, 0 failed (рис. 5).
- Ролі в БД відповідають seed: `admin` — Administrator, `alice`, `bob` — Reporter, `morgan` — Analyst (рис. 6).

## 3. Політика і матриця доступу

Для чужого ресурсу обрано **404 Not Found**: відповіді для чужого й неіснуючого `id` однакові (`404`, `application/problem+json`, title «Інцидент не знайдено»). Для дій, закритих за роллю (list/search/summary, triage, internal comment), повертається `403`. Повна матриця, рядки реалізації та обґрунтування — у `docs/access-matrix.md` (рис. 7).

## 4. Основний finding: IDOR/BOLA у `GET /api/incidents/{id}`

1. **Контекст.** Ресурс `Incident`, action — details/read. Суб'єкти: Alice і Bob (Reporter), Morgan (Analyst).
2. **Гіпотеза.** Alice зможе прочитати інцидент Bob підстановкою його `id`.
3. **Стан до** (vulnerable commit `88880157…`, рис. 8). Запит з cookie Alice:
   - `--user alice --incident alice` → `login_status=204`, `read_status=200`, інцидент Alice;
   - `--user alice --incident bob` → `login_status=204`, `read_status=200`, `{"id": "20000000-…-0002", "title": "Невідома спроба входу", "ownerDisplayName": "Боб Мельник"}`.
   Додатково: маршрут details не мав `RequireAuthorization()`, тобто був доступний і без автентифікації (друга окрема діра).
4. **Першопричина.** `IncidentQueries.GetDetailsAsync` шукав інцидент лише за `id` і не отримував суб'єкта; endpoint не мав ні owner-обмеження, ні ресурсного рішення.
5. **Виправлення** (fixed commit `beb496d8…`, рис. 9–11):
   - `GetDetailsAsync(id, requestingUserId, isPrivilegedReader, ct)`: умова `id == id && (isPrivilegedReader || OwnerUserId == requestingUserId)` у самому `Where`; чужий рядок не завантажується;
   - ідентифікатор користувача береться з `ClaimTypes.NameIdentifier` у `HttpContext.User` через `Guid.TryParse`, роль Analyst — через `IsInRole(DbSeeder.AnalystRole)`; нічого не береться з body чи URL;
   - до маршруту додано `.RequireAuthorization()` (анонім → 401, не redirect).
6. **Retest** (рис. 18). `alice → bob`: `login_status=204`, `read_status=404`, тіло `{"title": "Інцидент не знайдено", "status": 404, "traceId": "…"}`; даних Bob немає.
7. **Позитивна регресія.** `alice → alice`: `200` з даними Alice; Morgan (Analyst) читає інцидент Alice (тест A-03R).
8. **Залишковий ризик** — розділ 7.

Схема рішення: запит Alice з `id` → cookie формує перевірений principal → `Where` з правилом owner/Analyst → знайдено → `200`; не знайдено (чужий або неіснуючий) → однаковий `404`; mutation виконується лише після того, як запис пройшов `Where`.

## 5. Розширення охоплення

- **Update** (`PUT /api/incidents/{id}`, commit `dcec5ce8…`). `UpdateIncidentRequest` містить лише `title`, `description`, `severity`, `occurredAtUtc`. Спершу валідація формату (без звернення до БД), потім `UpdateContentAsync` з умовою `OwnerUserId` у `Where`; запис завантажується з відстеженням (без `AsNoTracking`). Ручна перевірка: Alice → `PUT` на інцидент Bob → `404` (рис. 23).
- **List** (commit перед списком, рис. 24–26). `GetListAsync(status, ownerUserId?)`: Guid → лише власні (Reporter), `null` → усі (Analyst); роль поза Reporter/Analyst → `403`.
- **Delete** (commit `546f688c…`, рис. 29–33). Той самий принцип «owner у `Where`»; успіх — `204`, чужий і неіснуючий — `404`. Побічно виправлено нестабільність тестів: login rate limiter у середовищі Development партиціонується за заголовком `X-Test-Partition` (рис. 34–35); у production заголовок ігнорується.
- **Triage** (commit `e44a0368…`, рис. 38–43). Роль Analyst перевіряється в endpoint до звернення до БД (Reporter/Administrator → `403`); потім сервер читає поточний статус, `New` → `Triaged` встановлює сам, інакше `409 Conflict`; неіснуючий `id` → `404`.
- **Internal comment** (commit `cee60041…`, рис. 44–49). Додано `comment-3` (`30000000-0000-0000-0000-000000000003`, `IsInternal = true`, автор Morgan, інцидент Alice). `GET /api/incident-comments/{id}` доступний лише Analyst; Reporter (навіть власник інциденту) і Administrator → `403`, анонім → `401`.
- **A-11** (commit `b9794f7e…`, рис. 50–56). `search` і `severity-summary` захищені `RequireAuthorization()` і обмежені за власником у запиті (у `search` — до сортування й `Take(50)`; у `severity-summary` — до групування). Роль поза Reporter/Analyst → `403`.

## 6. Додатковий дефект доступу (A-11 / A-01): витік існування ресурсу через `409`

Під час огляду data-access points виявлено, що перевірка дубліката `title` у `POST /api/incidents` шукала збіг серед усіх інцидентів незалежно від власника.

- **До** (рис. 57). Alice створює інцидент з `title`, що вже має активний інцидент Bob → `409 Conflict`, хоча `GET /api/incidents/{id}` для того самого ресурсу повертає `404`. Два endpoint-и давали суперечливі сигнали про існування ресурсу.
- **Першопричина.** Предикат `AnyAsync` не містив умови `OwnerUserId`.
- **Виправлення** (рис. 58, commit `b109c5c7…`). До предиката додано `item.OwnerUserId == ownerUserId`; унікальність `title` рахується в межах власних інцидентів.
- **Після** (рис. 59–60). Автоматичний тест `A02_DuplicateTitleAcrossDifferentOwners_DoesNotLeakExistence`: Bob і Alice створюють інциденти з однаковим `title`, обидва → `201 Created`. Створені записи прибираються у `finally`. Підсумок: 50 тестів, 0 failed.

## 7. Огляд data-access points та залишковий ризик

Огляд усіх точок доступу до БД наведено в таблиці 1 (рис. 61): усі LINQ-запити до `Incident` мають owner/role-умову або навмисно її не мають (`TriageAsync`, `GetCommentAsync` — роль перевіряється в endpoint); `DbSeeder`/`Lab02Seed`/`DatabaseBootstrap` — службовий код поза HTTP.

Залишковий ризик — докладно в `docs/access-matrix.md`, розділ «Залишковий ризик». Коротко:

- CSRF для cookie-authenticated mutating endpoint-ів — задокументований борг ЛР 3, закривається в ЛР 6; owner-check не компенсує його відсутність.
- Роль фіксується в cookie під час login: зміна ролі в БД діє після повторного входу.
- Немає optimistic concurrency для `triage` (сценарій від викладача не надавався).
- Structured audit `authorization.denied` не реалізовано (розділ 8).
- Administrator не має додаткових прав (least privilege).

## 8. Доказова таблиця

| ID | Рівень | Сценарій | Передумови | Дія | Очікувано | Фактично | Доказ |
|---|---|---|---|---|---|---|---|
| A-01 | добрий | Анонімний доступ | немає cookie | `GET` details, `GET` list, `DELETE`, `POST …/triage`, `GET` search, `GET` severity-summary, `GET` internal comment | 401, не HTML redirect | Тести проходять (`401`) | автоматичні тести, рис. 12, 26, 33, 41, 47, 53–54 |
| A-02 | достатній | Власний ресурс | Alice, seed-інцидент | `GET` details; власне `DELETE` | allow | `200`; `204`, після видалення `404` | рис. 12, 32 |
| A-03 | достатній | Чужий ресурс | Alice, інцидент Bob | `GET`, `DELETE` | 404, `application/problem+json` | `404`, `application/problem+json`; ручний `PUT` → `404` | рис. 13, 23, 33; стан Bob після `PUT`/`DELETE` повторним читанням **не перевірено** |
| A-03R | достатній | Аналітичний read | Morgan, інцидент Alice | `GET` details | allow | `200` | рис. 13 |
| A-04 | добрий | Чужий update/delete | Alice, інцидент Bob | `PUT`, `DELETE` | deny, стан без змін | `404` для обох; автоматичний state assertion є лише неявно (умова в `Where`) | рис. 23, 33 |
| A-05 | добрий | List | Alice | `GET` list, search, severity-summary | лише дозволена множина | список не містить інцидент Bob; сума summary < 5 | рис. 26, 53–54 |
| A-06 | добрий | Вертикальне підвищення | Alice (Reporter) | `POST …/triage`; `GET` internal comment | deny | `403` (обидва) | рис. 40, 47 |
| A-07 | добрий | Дозволена привілейована дія | Morgan, новий інцидент у статусі `New` | `POST …/triage`; `GET` internal comment | allow | `204`; `200` з `isInternal = true` | рис. 40, 47 |
| A-08a/b | добрий | Overposting | Alice | `PUT` з підробленими owner/role/status | owner/role/status без змін | `UpdateIncidentRequest` не містить цих полів (контракт); окремого тесту A-08 **не виконано** | рис. 19–20 |
| A-09 | добрий | Audit denied | Reporter | `triage` | рядок `authorization.denied` з `traceId` | **не виконувалось** — audit-подія не реалізована | — |
| A-10 | добрий (політика 404) | Нерозрізнюваність 404 | Alice | чужий і неіснуючий id | однакові status/Content-Type/тіло | окремо перевірено `404` + `application/problem+json` для обох; порівняння тіл без `traceId` в одному тесті **не виконано** | рис. 13–14 |
| A-11 | відмінний | search, severity-summary | Alice | `GET` обох | лише дозволена множина | відповіді Alice не містять інцидентів Bob; додатковий дефект (`409`) виправлено | рис. 50–56, 57–60 |
| A-12 | добрий | Child + internal comment | Alice (Reporter) | `GET` `/api/incident-comments/{id}` | deny | `403` для `comment-3` (internal, власний інцидент Alice); запит до `comment-2` (інцидент Bob) окремо **не виконувався** | рис. 47 |

Останній повний запуск: `dotnet test … -c Release` → `total: 50, failed: 0, succeeded: 50, skipped: 0` (рис. 60). Динаміка: 25 → 29 → 33 → 35 → 38 → 42 → 45 → 49 → 50.

## 9. Стан подання та що лишилося

- [ ] Browser client (крок 8): показ деталей Alice і відмови для Bob через `textContent` — скриншотів у матеріалах немає.
- [ ] A-08a/b, A-09 (audit-подія `authorization.denied` з тим самим `traceId`, що у відповіді), A-10 (порівняння тіл) та A-12 для `comment-2` — не виконано.
- [ ] Тест `A-03R` для мутації: стан Bob після відмови не порівнювався повторним читанням.
- [ ] Створити тег `v0.4.0` на `b109c5c7…` та окремим commit внести hashes у звіт.
- [ ] Відмінний рівень: відокремлений resource-based handler (`IAuthorizationService`) не застосовано — використано query scoping і перевірку ролі в endpoint. Це потрібно або реалізувати, або обґрунтувати як «рівнозначну policy».

## 10. Використання генеративного ШІ

Використовувався ШІ-асистент: пояснення методичних вимог, діагностика помилок тестів (зокрема rate limiter), допомога з реалізацією owner-scoped запитів і структуруванням звіту. Код і твердження перевірялись запуском тестів і ручними HTTP-запитами та адаптовані до структури власного проєкту.

## 11. Висновок

На vulnerable commit відтворено IDOR/BOLA: Alice з власною cookie отримувала `200` і дані інциденту Bob, а маршрут details був доступним навіть анонімно. Першопричина — запит лише за `id` без суб'єкта. Виправлення виконано обмеженням запиту за суб'єктом (owner/Analyst у `Where`) і `RequireAuthorization()`; після нього Alice отримує `404` для чужого ресурсу, власний ресурс доступний, Analyst читає для аналізу. Те саме правило поширено на update, delete, list, search, severity-summary; додано роль-обмежений triage (`New → Triaged`) та internal comment. Знайдено й усунено додатковий дефект — витік існування чужого інциденту через `409` при перевірці дубліката `title`. Повний набір із 50 автоматичних тестів проходить. Окремі пункти (audit, A-08, A-10, browser client, тег) лишаються для завершення — розділ 9.
