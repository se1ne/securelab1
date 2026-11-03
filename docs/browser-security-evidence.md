# Докази безпеки браузера (DEL-01)

Рівень: **відмінний («Відмінно»)**. Рівні накопичувальні; нижче заповнено всі розділи. Паролів, значень cookie/token і експорту browser storage тут немає.

## Стенд і Git-стан (Для всіх)

ОС, browser, origins: Windows 11; Firefox 159.0 (приватні вікна для сеансів Morgan); API і штатний клієнт — `http://localhost:5080`; навчальні probes — `http://localhost:4173` (дозволений) і `http://localhost:4174` (контроль). Середовище Development; PostgreSQL у Docker; .NET 10.

Receipt `.scaffolds/lab-05.json`: `release` = `lab-05-start-v1`, `inherits` = `v0.4.0`, `base_commit` = `0000e64fcfdf73523a264c1d55bbc9f3693d6b4e`, `entry_parent` = `0000e64fcfdf73523a264c1d55bbc9f3693d6b4e` (рис. 3).

Git-стан (гілка `lab/5-browser-xss`, створена від `v0.4.0`):

| Крок | Commit |
|---|---|
| Vulnerable (scaffold) | `84697d859d696371ec5b1b0ef7a4cf83b17bea08` |
| Seed marker-коментаря | `f77b21d` |
| **Fixed: safe DOM для Description і comments** | `d15159f` |
| CORS-політика для 4173 (Development) | `19f8c57` |
| `AllowCredentials()` для 4173 | `b62b4f6` |
| Serialized-колекція для cookie/authentication тестів | `e5b9cf3` |
| CSP enforcement | `c3fd65d` |
| DOM-тест опису | `5ff305e` |
| DOM-тест коментарів | `8b219aa` |
| Кінцевий fixed commit (з документами) | `<FINAL_COMMIT>` |

`v0.5.0` → `<FINAL_COMMIT>`; `main` = fast-forward до `<FINAL_COMMIT>`; передавання: `<приватний remote / lab05.bundle>`.

Механізм сеансу (Application → Storage → Cookies → `http://localhost:5080`, без Value):

| Назва | Domain | Path | HttpOnly | SameSite | Secure | Expires |
|---|---|---|---|---|---|---|
| `.AspNetCore.Identity.Application` | `localhost` (HostOnly) | `/` | true | Lax | false (HTTP на localhost) | Session |

## Гіпотеза й REG-XSS-01 (Для всіх)

Карта Description — `docs/source-to-sink.md`.

**Гіпотеза.** Текст `Incident.Description` (і `IncidentComment.Text`) надходить із форми через `POST /api/incidents`, зберігається в БД як звичайний рядок, повертається в JSON і в `browser-lab.js` потрапляє в `innerHTML`. Якщо рядок містить HTML, браузер створить елемент і виконає обробник подій. Очікую stored XSS, який спрацює в сеансі іншого користувача (Morgan, Analyst).

**Передумови.** Vulnerable commit `84697d8`; reset: `dotnet run --project src/SecureLab.Api -- --reset-database` (змінна `SeedUsers__Password` задана); користувачі alice і morgan; marker — єдиний рядок з `resources/lab05-marker.txt`: `<img src=x onerror="document.querySelector('#lab05-marker-target').setAttribute('data-lab05-marker','executed')">`. Marker лише ставить атрибут на прихованому `#lab05-marker-target`, не читає cookie/storage і не робить зовнішніх запитів. Запис Alice: `b4285b47-81b4-4bac-aa5e-e3bfe1553647`.

| Спостереження | До fix | Після fix | Посилання на доказ |
|---|---|---|---|
| Значення в БД/API | `description` у POST payload і GET JSON — marker символ у символ | той самий запис, той самий JSON; значення не змінювалося | рис. 12 (до); рис. 20–22 (після, той самий запис); для коментаря — рис. 35 і 93 |
| DOM основного Description | у `#description` створено дочірній `<img src="x" onerror="…">` | один текстовий вузол у лапках, `<img>` немає | рис. 11, 15–16 (до); рис. 20–21, 25 (після) |
| Дія marker | команда перевірки повертає `'executed'`; у Network запит `x` | команда перевірки повертає `null`; запиту `x` немає | рис. 9, 12, 16 (до); рис. 19, 22–23 (після) |
| Апостроф/лапки, `5 < 7`, Unicode, HTML-like рядок | — | текст `5 < 7 і 9 > 3, "лапки", 'апостроф', & Привіт, Їжак, 日本語 😀` відображено без пошкоджень; HTML-like рядок показано як текст | рис. 26, 90, 77 |
| Довжина за власними правилами ЛР 2 | — | 3900 символів: `POST` 201, `GET` 200, помилок немає (межа колонки в starter — 4000) | рис. 91 |
| Вікно Morgan: GET і перевірка marker | `null` → `GET: 200` → `'executed'` (stored XSS у сеансі Analyst) | `null` → `GET: 200` → `null` | рис. 13–16 (до); рис. 24–25 (після). Контроль Bob за погодженням з викладачем не виконувався |

**Finding.**
- Актив: сеанс браузера й дані, доступні від імені користувача.
- Передумови: локальний тестовий акаунт із контролем над текстовим полем.
- Першопричина: недовірене значення з API потрапляє в HTML-парсер через `innerHTML` у `browser-lab.js` (`load()`, рядки 10 і 14).
- Вплив на стенді: marker виконав лише безпечну локальну DOM-дію в сеансі Morgan (Analyst).
- Safe DOM diff: `#description.innerHTML = current.description` → `replaceChildren(document.createTextNode(current.description))`; `paragraph.innerHTML = comment.text` → `createTextElement("p", comment.text)` (helper кладе значення лише в `textContent`).
- Retest: той самий marker не виконується, DOM містить текстовий вузол.
- Залишковий ризик: інші поля й клієнти поза дослідженим flow; нове поле з HTML-контекстом знову стане sink.

**REG-XSS-01 (повторювана процедура).**

| Поле | Вміст |
|---|---|
| Передумови | commit `<FINAL_COMMIT>`; reset-команда вище; alice і morgan; Firefox; origin 5080 |
| Вхід | marker з `resources/lab05-marker.txt` |
| Кроки | 1) reset і запуск API. 2) Alice входить через `/auth-lab.html`; у `/browser-lab.html` команда `document.querySelector("#lab05-marker-target").getAttribute("data-lab05-marker")` → `null`. 3) Створює інцидент: назва нейтральна, опис = marker; копіює Guid. 4) Приватне вікно: Morgan входить, відкриває `/browser-lab.html`, вставляє Guid, «Прочитати». 5) У Console `tests/browser/description-dom.js` і `tests/browser/comments-dom.js` (спершу набрати `allow pasting`). |
| Очікуваний результат | marker не виконується (`null`); `#description` містить текстовий вузол, `<img>` немає; запиту `x` у Network немає; обидва тести дають PASS; звичайний текст із лапками, `<`, `>`, Unicode відображається правильно |
| Негативний контроль | на `84697d8` (старий `browser-lab.js`) marker виконується (`'executed'`, `<img>` у DOM), DOM-тести дають FAIL |
| Доказ | Network/Elements; файли `Client/browser-lab.js`, `tests/browser/*.js` |

## CORS і REG-CORS-01 (Для всіх)

Прогноз за теорією SOP/CORS (таблиця описує очікування; фактичні результати нижче збіглися з ним):

| Сценарій | Чи доходить request до API? | Чи може JavaScript прочитати response? | Чому |
|---|---|---|---|
| same-origin 5080 → API | так | так | CORS не потрібен |
| simple GET 4173 → API | так | ні без valid CORS | SOP/CORS у браузері |
| simple GET 4174 → API | так | ні | origin не в allowlist |
| curl/.http → API | так | не застосовується | це не JavaScript у браузері |
| preflighted 4173 → API | спочатку OPTIONS; actual GET залежить від відповіді | ні без успішного preflight | preflight і CORS |

Команди запуску probes (з кореня проєкту, де `global.json`):
```powershell
py -3 -m http.server 4173 --bind localhost --directory demonstrations/cors-probe
py -3 -m http.server 4174 --bind localhost --directory demonstrations/cors-probe
dotnet run --project src/SecureLab.Api
```
Політика `Lab05BrowserProbe` — лише Development, один exact origin `http://localhost:4173`, метод `GET`, заголовок `X-Lab-Cors-Probe`, `.AllowCredentials()`; `http://localhost:4174` — негативний контроль. `AllowAnyOrigin()`, `AllowAnyMethod()`, `AllowAnyHeader()` не використано. Реєстрація (`AddCors`) — перед `builder.Build()`; в конвеєрі `UseRouting()` і умовний `UseCors("Lab05BrowserProbe")` стоять перед `UseAuthentication()`.

| Клієнт / простий запит | До policy | Fixed state | Status, ACAO, Console / доказ |
|---|---|---|---|
| Same-origin 5080 | працює без CORS | працює | рис. 43; `GET /health` 200 |
| Allowed 4173 | `Failed to fetch`, немає `Access-Control-Allow-Origin` | `{status: 200, body: '{"status":"ready"}'}`; `Access-Control-Allow-Origin: http://localhost:4173` | рис. 41 (до); рис. 46, 48 (після) |
| Disallowed 4174 | заблоковано, ACAO немає | заблоковано (CORS header missing); запит дійшов до API (статус 200 на сервері) | рис. 41 (до); рис. 47 (після) |
| Direct HTTP / curl | — | читає відповідь 200 незалежно від `Origin` | рис. 61–64 |

**REG-CORS-01.**
- Browser evidence: 4173 — відповідь доступна JavaScript (рис. 46, 48); 4174 — `Failed to fetch`, у Network запит до `http://localhost:5080/health` з `Origin: http://localhost:4174`, ACAO немає (рис. 47, 50).
- Дві actual HTTP-відповіді з fixed state (рис. 94):
```powershell
curl.exe -sS -D - -o NUL -H "Origin: http://localhost:4173" "http://localhost:5080/health"
curl.exe -sS -D - -o NUL -H "Origin: http://localhost:4174" "http://localhost:5080/health"
```
Для `Origin: 4173` — `200`, `Access-Control-Allow-Origin: http://localhost:4173`, `Access-Control-Allow-Credentials: true`. Для `Origin: 4174` — `200`, жодного `Access-Control-*`. В обох є `nosniff`, `no-referrer` і CSP.
- Перевірка порядку (401 без cross-origin cookie): `fetch("http://localhost:5080/api/incidents")` зі сторінки 4173 повертає `401`, у відповіді `Access-Control-Allow-Origin: http://localhost:4173` — JavaScript прочитав саме відмову, отже `UseCors` стоїть перед `UseAuthentication` (рис. 51, 59).
- Різниця browser/direct HTTP: CORS — правило браузера для читання cross-origin відповіді скриптом. Запит до API доходить в обох випадках; `curl` не застосовує SOP і читає відповідь. Захист даних дають автентифікація й авторизація API: без cookie `curl` отримує `401` (рис. 64).

## Додатково для Добре та Відмінно

**Другий flow IncidentComment.Text.** Публічний seed-коментар `30000000-0000-0000-0000-000000000005` (автор Morgan, інцидент Alice `20000000-…-0001`, `IsInternal = false`, commit `f77b21d`) містить marker. До fix: у `#comments` елемент `<img>`, команда перевірки `'executed'` (рис. 30–35). Після fix: коментар видно як текст, `null` (рис. 36–37). Похідні counts: у тестах ЛР 4 кількість коментарів не перевірялася, тести проходять 50/50 (рис. 28). Єдиний safe helper `createTextElement(tagName, text)` кладе значення лише в `textContent`; використано для коментарів, а для опису — `createTextNode` (рис. 18).

**Preflight і cookie-дослід.**
- Preflight з 4173: `OPTIONS /health` → 204 з `Access-Control-Allow-Origin: http://localhost:4173`, `-Methods: GET`, `-Headers: X-Lab-Cors-Probe`; запит містить `Access-Control-Request-Method: GET` і `Access-Control-Request-Headers: x-lab-cors-probe`; після нього `GET` 200 (рис. 49). До policy той самий `OPTIONS` дав 405 і actual GET не надсилався (рис. 42).
- Preflight з 4174: `OPTIONS` → 204 без `Access-Control-*`, браузер заблокував запит і actual GET не надіслав (рис. 50).
- Cookie-дослід: 4173 із `credentials: "include"` після входу Alice — `200` зі списком, у запиті є `Cookie` і `Origin`, у відповіді `Access-Control-Allow-Origin: http://localhost:4173` і `Access-Control-Allow-Credentials: true` (рис. 54–55). 4174 — відповідь не надано скрипту, але запит пішов із cookie й виконався (рис. 56–57). Негативний контроль без `AllowCredentials()` — помилка про `Access-Control-Allow-Credentials` (рис. 58). Приватне вікно без входу — `401` з CORS-заголовками (рис. 59).
- Кінцевий стан: `AllowCredentials()` лишається лише в Development-політиці для єдиного origin `http://localhost:4173`. Review XSS/CORS/CSRF/authorization — у звіті DEL-03.

**CSP (фактичні ресурси застосунку).** Клієнт (`/`, `/browser-lab.html`, `/auth-lab.html`) завантажує лише власні HTML, `styles.css`, `app.js`, `browser-lab.js` з `http://localhost:5080`; зовнішніх шрифтів, скриптів і CDN немає; API — той самий origin.

| Директива CSP | Фактичні ресурси застосунку | Обране джерело / причина |
|---|---|---|
| default-src | усі типи ресурсів — власний origin | `'self'` як резервне правило для неявних типів |
| script-src | лише `app.js`, `browser-lab.js` | не задано окремо: діє `default-src 'self'`; inline-скриптів і `unsafe-inline` немає |
| style-src | `styles.css` | діє `default-src 'self'`; inline-стилів немає |
| connect-src | запити `fetch` до API на 5080 | діє `default-src 'self'` (клієнт і API — один origin); origin 4173/4174 — лише тимчасовий CORS-стенд, до CSP не додано |
| img-src | власних зображень немає | діє `default-src 'self'`; `<img src="http://localhost:4173/x.png">` блокується (рис. 73–74) |
| frame-ancestors | вбудовування не потрібне | `'none'` (немає fallback до `default-src`, тому вказано явно) |

Політика: `default-src 'self'; frame-ancestors 'none'`. Місце зміни — наявна спільна middleware в `Program.cs` (`var csp = …` перед `app.Use(...)`, заголовок ставиться, якщо шлях не `/scalar` у Development). Ту саму middleware змінено при переході від report-only до enforcement, другої не додавалося.
- Enforcement: документ `browser-lab.html` зі статусом 200, у Response Headers один заголовок `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'` (рис. 71); три сторінки (`/`, `/browser-lab.html`, `/auth-lab.html`) із входом, читанням і створенням інциденту працюють без повідомлень CSP (рис. 72, 76–78). Кероване порушення `new Image().src = "http://localhost:4173/x.png"` — запит заблоковано, в Network статус «CSP» (рис. 73–74). `curl` показує заголовок (рис. 75).

| Header / control | Фактичне значення | Ризик і межа захисту / policy rationale |
|---|---|---|
| X-Content-Type-Options | `nosniff` | браузер не вгадує тип файлу, тож скрипт не виконається під виглядом іншого типу; не замінює правильний `Content-Type` і перевірку даних |
| Referrer-Policy | `no-referrer` | адреса сторінки не потрапляє в `Referer` на інші сайти; клієнт не потребує `Referer` для навігації (усі сторінки одного origin); не замінює заборону класти секрети в URL |
| frame-ancestors | `'none'` | сторінку не можна вбудувати в чужий frame (clickjacking); не замінює авторизацію чи виправлення XSS |

## Додатково для Відмінно

**DOM-тест.** `tests/browser/description-dom.js` і `tests/browser/comments-dom.js` (запускаються в Console справжнього браузера Firefox 159.0 на `/browser-lab.html`, спершу `allow pasting`).
- Vulnerable `84697d8`: `description-dom.js` — FAIL `Text changed` (рис. 82, 84); `comments-dom.js` — FAIL `Comment 1: text changed` (рис. 88).
- Fixed: `comments-dom.js` — PASS (рис. 87); `description-dom.js` — PASS (рис. 82). Тести падають на небезпечному sink незалежно від CSP.

**Comments, повторний render і позитивні рядки.** `comments-dom.js` двічі викликає `load()` і перевіряє, що кількість дочірніх елементів збігається з `comments.length` (без дублювання), текст кожного `comments[i].text` збігається з `textContent` і `childElementCount === 0`. Позитивні рядки: рис. 26, 90, 91.

**CSP report-only → enforcement.**
- Report-only (`Content-Security-Policy-Report-Only`): документ 200, один заголовок (рис. 66); основний flow без порушень у приватному вікні (рис. 67); кероване порушення дало повідомлення «Report-Only policy … would block … `default-src 'self'`» без блокування (рис. 68); `curl` (рис. 69). Firefox додатково повідомив, що report-only політика без `report-uri`/`report-to` нікуди не надсилає звіти — для стенда це очікувано.
- Enforcement (`Content-Security-Policy`): рис. 70–78. Різниця: у report-only завантаження лише логується, у enforcement — блокується (рис. 73–74).
- Повідомлення від `autoconsent.js` у Console належать розширенню браузера, а не застосунку; політику через них не послаблено.

**safe-url.js / атрибут.** Рис. 92: `safeHttpUrl` розбирає значення через `new URL` і пропускає лише `http:`/`https:`; `javascript:`, регістр і пробіл на початку, некоректний `http://[bad` → `null`; у `<a>` є `href` і немає `onclick`. Нейтральний приклад, у застосунок не додавався. Пояснення text/attribute/URL/JavaScript і ризик third-party scripts — у звіті DEL-03.

Додаткових DEL, навчальних демо або нового журналу не подаю.
