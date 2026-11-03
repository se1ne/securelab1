# Звіт до лабораторної роботи № 5

**Тема:** Безпека браузера: XSS, DOM і межі CORS
**Виконав:** Лімаз Федір Сергійович, КБ-41
**Варіант:** baseline 2-A «Трекер інцидентів» (спільний сценарій, окремого номера варіанта немає)
**Рівень виконання:** відмінний («Відмінно»)
**ОС і браузер:** Windows 11; Firefox 159.0 (основний), приватні вікна для сеансу Morgan

## 1. Ідентифікація стану

- Гілка: `lab/5-browser-xss` (від тегу `v0.4.0`, commit `0000e64fcfdf73523a264c1d55bbc9f3693d6b4e`).
- Scaffold: `release` = `lab-05-start-v1`, `inherits` = `v0.4.0`, `base_commit` = `entry_parent` = `0000e64fcfdf73523a264c1d55bbc9f3693d6b4e` (рис. 3).
- Vulnerable commit: `84697d859d696371ec5b1b0ef7a4cf83b17bea08` (установлений scaffold з навмисним `innerHTML`).
- Fixed commit (XSS, safe DOM для Description і comments): `d15159f` (рис. 38).
- Проміжні commits:

| Крок | Commit |
|---|---|
| Seed marker-коментаря | `f77b21d` |
| CORS-політика для 4173 (Development) | `19f8c57` |
| `AllowCredentials()` для 4173 | `b62b4f6` |
| Serialized-колекція для cookie/authentication тестів | `e5b9cf3` |
| CSP enforcement | `c3fd65d` |
| DOM-тест опису | `5ff305e` |
| DOM-тест коментарів | `8b219aa` |

- Кінцевий перевірений commit для тегу: `985120699e456ae0541b88aa1c457aad68be193d`.
- Тег: `v0.5.0` → `985120699e456ae0541b88aa1c457aad68be193d`; `main` fast-forward до цього commit; передано: `<приватний remote або lab05.bundle>`.
- Виправлення стану ЛР 4: не потрібне. Стартові перевірки пройшли (рис. 1–4).

## 2. Стартова перевірка

- Гілку створено від `v0.4.0` (рис. 1). Installer: dry run показав п'ять шляхів, потім запис (рис. 2); receipt і commit scaffold (рис. 3).
- Усі тести ЛР 4 проходять, стенд запущено (рис. 4). Вхід Alice і `GET: 200` для seed-інциденту (рис. 5–8).
- Після додавання seed-коментаря й `reset` тести проходять 50/50 (рис. 28). Тести, що падали через ручні записи в БД, перевірено після `--reset-database`; два тести отримали атрибут `[Collection("Serialized")]` без зміни `Assert` (commit `e5b9cf3`).

## 3. Основний finding: stored XSS у Incident.Description

1. **Актив.** Сеанс браузера й дані, доступні від імені користувача.
2. **Передумови.** Локальний тестовий акаунт (Alice) із контролем над текстовим полем; привілейований глядач Morgan (Analyst).
3. **Гіпотеза.** Текст опису, збережений Alice, виконається в сеансі іншого користувача, бо клієнт відображає його через `innerHTML`.
4. **Стан до** (vulnerable `84697d8`, рис. 9–17):
   - команда перевірки `document.querySelector("#lab05-marker-target").getAttribute("data-lab05-marker")` → `null` (рис. 9);
   - Alice створює інцидент із canonical marker в описі (рис. 10): `POST` 201, `GET` 200; замість опису «зламана» картинка, у `#description` створено `<img src="x" onerror="…">`, `data-lab05-marker="executed"` (рис. 11–12). Guid запису `b4285b47-81b4-4bac-aa5e-e3bfe1553647`;
   - Morgan (приватне вікно): `null` → `GET: 200` → `'executed'` (рис. 13–16). Код, збережений Alice, виконався в сеансі Analyst — це **stored XSS**;
   - sinks: `browser-lab.js`, рядок 10 (`#description.innerHTML`) і рядок 14 (`paragraph.innerHTML = comment.text`) (рис. 17).
5. **Першопричина.** Недовірене значення з API (збережений текст користувача) потрапляє в HTML-парсер через `innerHTML`. Авторизація не допомагає: вона перевіряє право читати запис, а не спосіб відображення. Валідація теж: `<`, `>`, лапки — допустимий звичайний текст.
6. **Виправлення** (`d15159f`, рис. 18, 38): у `browser-lab.js` додано helper `createTextElement(tagName, text)` (значення тільки в `textContent`); опис виводиться через `replaceChildren(document.createTextNode(current.description))`, коментарі — через `createTextElement("p", comment.text)`. Фільтра слова `script` чи blacklist немає; значення в БД і API response не змінювалися. Рядок `elements.description.value = current.description` лишився: властивість `value` не розбирається як HTML.
7. **Retest** (рис. 19–25): той самий запис, той самий marker. Alice: `null` → у `#description` один текстовий вузол із текстом marker, `<img>` немає, запиту `x` немає, `null`. Morgan: `null` → `GET: 200` → `null`.
8. **Позитивна регресія** (рис. 26, 90, 91): `5 < 7 і 9 > 3, "лапки", 'апостроф', & Привіт, Їжак, 日本語 😀` відображається без пошкоджень, response JSON містить те саме значення; рядок із 3900 символів збережено й показано без помилок.
9. **Залишковий ризик** — розділ 9.

Схема: поле форми → `POST /api/incidents` → `Incident.Description` у БД → `GET` JSON `description` → `load()` → `#description`. Повна карта — `docs/source-to-sink.md`.

## 4. Другий sink: IncidentComment.Text

- Seed-коментар `30000000-0000-0000-0000-000000000005` (публічний, автор Morgan, інцидент Alice) містить marker (рис. 27–29, commit `f77b21d`). Окремого endpoint створення коментаря немає.
- До fix (рис. 30–35): у `#comments` елемент `<img>`, команда перевірки `'executed'`; у Network видно всі коментарі інциденту.
- Після fix (рис. 36–37): коментар виведено як текст, `null`. Response JSON з marker-коментарем однаковий до й після (рис. 35 і 93).
- Обидва поля (`description`, `comments[].text`) виводяться без `innerHTML`; helper `createTextElement` — єдиний спосіб створення елементів з текстом.

## 5. CORS: origin, preflight, credentials

- **Origins:** API і штатний клієнт — `http://localhost:5080`; дозволений probe — `http://localhost:4173`; контрольний — `http://localhost:4174`. Origin = схема + host + порт, тому різні порти — різні origins.
- **Стан до** (рис. 39–43): прості запити з обох probes → `Failed to fetch`, у відповіді немає `Access-Control-Allow-Origin`; запит із заголовком `X-Lab-Cors-Probe` → `OPTIONS` 405, actual GET не надсилався. Same-origin 5080 працює (рис. 43).
- **Політика** (`19f8c57`, рис. 44–45): `Lab05BrowserProbe` — лише Development, exact origin `http://localhost:4173`, метод `GET`, заголовок `X-Lab-Cors-Probe`; `UseRouting()` і умовний `UseCors` перед `UseAuthentication`. Wildcard-політик немає.
- **Стан після** (рис. 46–51): 4173 — простий запит і запит із заголовком дають 200, є `Access-Control-Allow-Origin: http://localhost:4173`; preflight `OPTIONS` 204 з `Allow-Origin`, `Allow-Methods: GET`, `Allow-Headers: X-Lab-Cors-Probe`, потім `GET` 200 (рис. 49). 4174 — запит дійшов до API (200), але браузер не віддав відповідь скрипту; `OPTIONS` 204 без `Access-Control-*`, actual GET не надіслано (рис. 47, 50). Запит без cookie до `/api/incidents` зі сторінки 4173 → `401` з CORS-заголовком: `UseCors` працює до автентифікації (рис. 51).
- **Credentials** (`b62b4f6`, рис. 53–60): `AllowCredentials()` разом із `credentials: "include"` — 4173 отримує `200` і список, cookie надіслано, є `Access-Control-Allow-Credentials: true` (рис. 54–55); 4174 — відповідь не надано скрипту, запит із cookie виконано (рис. 56–57); без `AllowCredentials()` — помилка про `Access-Control-Allow-Credentials` (рис. 58); без входу — `401` з CORS-заголовками (рис. 59). Кінцевий стан: `AllowCredentials()` лише в Development-політиці для 4173.
- **Direct HTTP** (рис. 61–64): `curl.exe` читає `200` незалежно від `Origin`; для `Origin: 4173` є `Allow-Origin` і `Allow-Credentials`, для `4174` немає `Access-Control-*`; без cookie `/api/incidents` → `401`.
- **REG-CORS-01** на fixed state — рис. 94 (дві відповіді `curl` для `Origin` 4173 і 4174).

Підсумок:

| Клієнт | Статус API | Відповідь доступна коду сторінки | Що застосовано |
|---|---|---|---|
| браузер, same-origin 5080 | 200 | так | CORS не потрібен, діють автентифікація й авторизація |
| браузер, probe 4173 | 200 | так | CORS-політика збіглася; перевірки API діють окремо |
| браузер, probe 4174 | 200 (запит виконано) | ні | правила браузера (SOP/CORS); перевірки API діють незалежно |
| `curl` | 200 / 401 | так, читає будь-яку відповідь | лише перевірки API, правил браузера немає |

## 6. CSP і browser headers

- Політика `default-src 'self'; frame-ancestors 'none'` додана в наявну middleware заголовків (`Program.cs`); `/scalar` у Development винесено з-під політики (залишковий ризик).
- **Report-only** (рис. 65–69): заголовок `Content-Security-Policy-Report-Only`, основний flow без порушень, кероване порушення `new Image().src = "http://localhost:4173/x.png"` лише логується («Report-Only policy … would block»).
- **Enforcement** (`c3fd65d`, рис. 70–79): документ 200, один заголовок `Content-Security-Policy`; три сторінки працюють (вхід, читання, створення інциденту); те саме порушення блокується (Network: статус «CSP», запиту до 4173 немає).
- Повідомлення `autoconsent.js` у Console належать розширенню браузера; політику через них не послаблено, `unsafe-inline` не додавався.
- `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` і `frame-ancestors 'none'` перевірено на фактичних відповідях і обґрунтовано (таблиця 2 у звіті, `docs/browser-security-evidence.md`).
- Під CSP enforcement marker не виконується навіть на vulnerable-коді (браузер блокує inline-обробник, `script-src-attr`), але `<img>` у DOM усе одно створюється; тому висновок про виправлення sink зроблено за DOM-тестами, а не за відсутністю виконання (рис. 82, 88).

## 7. Review: XSS, CORS, CSRF, authorization

| Механізм | Що вирішує | Що не вирішує | У цій роботі |
|---|---|---|---|
| Authorization | чи має суб'єкт право на дію з ресурсом (ЛР 4) | як браузер інтерпретує текст у відповіді | Morgan мав право читати запис Alice, тому код Alice виконався саме в його сеансі |
| XSS-захист (safe DOM) | не дає тексту стати кодом на сторінці | чужі запити до API, права доступу | виправлено в sink: `textContent` / `createTextNode` |
| CORS | чи надає браузер cross-origin response скрипту | чи дійде запит до сервера; хто має право на дані | 4174 заблоковано для читання, але запит виконано; `curl` читає все |
| CSRF | чи змусили браузер користувача надіслати запит зі своєю cookie | читання відповіді, виконання чужого JavaScript | cookie йде з 4173 і 4174 (`SameSite=Lax`, один site); antiforgery — у ЛР 6 |

Висновок: CORS не є ні authentication, ні authorization, ні CSRF-захистом. Preflight лише питає браузер, чи можна надсилати запит; він не перевіряє права користувача. CSP — додатковий шар, який зменшує наслідки XSS, але не виправляє sink. HttpOnly cookie обмежує читання cookie з JavaScript, проте не зупиняє виконання injected code.

## 8. Регресії

- **REG-XSS-01** (процедуру, передумови, кроки, очікування й негативний контроль записано в `docs/browser-security-evidence.md`): Alice створює запис із marker, Morgan читає; marker не виконується, DOM містить текстовий вузол. Негативний контроль — `84697d8`.
- **REG-CORS-01:** browser evidence для 4173 і 4174 + дві відповіді `curl` з `Origin` 4173/4174 (рис. 94).
- **DOM-тести** (Console, Firefox 159.0): `tests/browser/description-dom.js` — FAIL на `84697d8` (`Text changed`, рис. 82, 84), PASS на fixed (рис. 82); `tests/browser/comments-dom.js` — FAIL на `84697d8` (`Comment 1: text changed`, рис. 88), PASS на fixed (рис. 87), перевіряє також повторний render без дублювання.
- **Автоматичні тести проєкту:** 50/50 (рис. 28).
- **Незмінність значення:** response JSON marker-коментаря однаковий до й після fix (рис. 35, 93); marker-запис опису читався до й після fix як той самий запис (рис. 12, 20–22).

## 9. Контексти виведення, залишковий ризик і third-party scripts

| Контекст | Правило безпечного виведення |
|---|---|
| Текстовий вузол | `textContent` або `createTextNode`: дані не розбираються як HTML |
| Значення атрибута | задавати через `setAttribute` або властивість елемента; не складати HTML-рядок із даних |
| URL (`href`, `src`) | розбирати через `new URL` і дозволяти лише `http:` та `https:` (`safeHttpUrl`); `javascript:` відхиляти, і `textContent` тут не допоможе (рис. 92) |
| JavaScript | не передавати дані в `eval`, `new Function`, рядкові обробники подій; inline-обробники блокує CSP |

Залишковий ризик:
- Нові поля або клієнти з `innerHTML` знову стануть sink. Додатковий шар (CSP) зменшує наслідки, але не замінює safe DOM.
- Сторінка `/scalar` у Development виключена з CSP; це сторонній UI-пакет з власними ресурсами, у production його немає (перевірка залежності — ЛР 6).
- Third-party scripts: у дослідженому клієнті (`/`, `/browser-lab.html`, `/auth-lab.html`) зовнішніх скриптів немає (`default-src 'self'`). Якщо їх додадуть, вони виконуються з правами сторінки; потрібні allowlist за host, Subresource Integrity і окрема оцінка.
- Cookie `Secure=false` на `http://localhost`: це особливість навчального стенда; у production потрібні HTTPS і `Secure`.
- CSRF для cookie-authenticated mutating endpoint-ів не закрито (ЛР 6); CORS його не замінює.
- Дослідження виконано лише у Firefox 159.0; результат може відрізнятися за формулюваннями повідомлень в інших браузерах.


## 10. Використання генеративного ШІ

Використовувався ШІ-асистент. Допомога: пояснення вимог методички.

## 11. Висновок

На vulnerable commit відтворено stored XSS: marker, збережений Alice в `Incident.Description`, виконався в сеансі Morgan (Analyst), бо `browser-lab.js` виводив значення через `innerHTML`; те саме стосувалося `IncidentComment.Text`. Першопричина — недовірений текст із API потрапляв у HTML-парсер, а не відсутність авторизації чи валідації. Виправлено sink: опис і коментарі тепер виводяться через `createTextNode`/`textContent` (helper `createTextElement`), значення в БД і API не змінювалися, marker відображається як звичайний текст, складні рядки з лапками, `<`, `>`, Unicode та текст на 3900 символів працюють. Для цього є два DOM-тести: FAIL на vulnerable і PASS на fixed.

Дослід CORS показав, що origin визначається схемою, host і портом; allowlist налаштовано на єдиний `http://localhost:4173` лише в Development; для 4174 браузер не надає відповідь скрипту, хоча запит доходить до API, а `curl` читає відповідь, бо SOP — правило браузера. CORS не замінює authentication, authorization чи CSRF-захист. CSP `default-src 'self'; frame-ancestors 'none'` перевірено спершу в report-only, потім у enforcement; разом із `nosniff` і `no-referrer` вона діє як додатковий шар, але не підміняє виправлення sink. Залишилося створити тег `v0.5.0`, перенести fixed state до `main` і передати Git-історію (розділ 10).

## 12. Відповіді на контрольні питання

1. **Чому value з БД може залишатися недовіреним?** Збереження не змінює походження значення: його вводив користувач. Валідація обмежує формат, але не перетворює текст на безпечну HTML-розмітку. Тому дані з БД або API недовірені до моменту відображення.
2. **Що таке source, transformation і sink у вашому flow?** Source — поле `description` у `form#edit`. Transformations — `POST /api/incidents`, збереження в `Incident.Description`, `GetDetailsAsync`, JSON `description`, `response.json()` у `load()`. Sink — `#description.innerHTML` (до fix) і `paragraph.innerHTML` для коментарів.
3. **Чим stored XSS відрізняється від reflected і DOM-based?** Stored — payload зберігається (БД) і виконується при пізнішому перегляді. Reflected — повертається з поточного запиту (наприклад, параметр URL у відповіді). DOM-based — небезпечне перетворення відбувається на клієнті (наприклад, `location.hash` → `innerHTML`). Ознаки не взаємовиключні: наш потік stored за походженням і DOM-sink за місцем виконання.
4. **Чому блокування `<script>` не усуває XSS?** Код виконується й без тега: `<img onerror=…>`, `<svg onload=…>`, `javascript:` в атрибутах. Blacklist залежить від відомих payload; виправляти треба sink.
5. **Коли `textContent`, а коли sanitizer?** `textContent`/`createTextNode` — коли значення є звичайним текстом (наш випадок). Sanitizer потрібен лише за окремої продуктової вимоги приймати обмежений HTML (підтримувана бібліотека на кшталт DOMPurify з мінімальним allowlist).
6. **Чому sanitizer не пишуть regular expression?** HTML — не регулярна мова, парсери браузерів допускають безліч форм запису; власний regex легко обійти. Потрібна перевірена бібліотека, яка розбирає HTML так само, як браузер.
7. **Origin складається з:** схеми (`http`), host (`localhost`) і порту (`5080`). `localhost:4173` і `localhost:5080` — різні origins.
8. **Що browser надсилає в preflight і хто його ініціює?** Браузер автоматично (не код сторінки) надсилає `OPTIONS` із `Origin`, `Access-Control-Request-Method` і `Access-Control-Request-Headers` перед запитом, що потребує дозволу (наприклад, нестандартний заголовок). У нас — `x-lab-cors-probe`.
9. **Хто оголошує CORS-політику і хто її застосовує?** API оголошує її заголовками `Access-Control-Allow-*`; застосовує її браузер: він вирішує, чи віддати відповідь скрипту. Сервер запит усе одно виконує.
10. **Чому `curl` читає response, коли browser script отримує CORS error?** SOP/CORS — правила браузера для веб-контенту. `curl` не виконує код сторінок і не застосовує ці правила; його обмежують лише перевірки API (наприклад, `401` без cookie).
11. **Чому CORS не є authorization і не замінює CSRF?** CORS не перевіряє права користувача й не зупиняє запит: простий cross-origin запит із cookie може змінити стан, навіть якщо відповідь недоступна скрипту (рис. 57). Authorization — на сервері, CSRF потребує окремого antiforgery (ЛР 6).
12. **Чому wildcard origin не поєднують із credentials?** Відповідь із cookie належить конкретному користувачу; дозвіл «усім origins» означав би, що будь-який сайт читає ці дані. Специфікація це забороняє, ASP.NET Core відхиляє таку політику під час запуску.
13. **Яку межу має CSP і чому вона не замінює safe DOM rendering?** CSP обмежує джерела ресурсів і виконання скриптів, тож зменшує наслідки XSS. Але елемент `<img>` створюється й під CSP (див. тести), а інші дані та HTML-ін'єкції лишаються. Sink треба виправляти.
14. **Який ризик зменшують `nosniff`, `Referrer-Policy`, `frame-ancestors`?** `nosniff` — MIME sniffing (скрипт під виглядом іншого типу). `Referrer-Policy: no-referrer` — витік адрес сторінок через `Referer`. `frame-ancestors 'none'` — вбудовування сторінки в чужий frame (clickjacking).

## 13. Межі перевірки

- Фактично перевірено: stored XSS у двох полях (Description, comments), safe DOM, CORS (4173, 4174, `curl`), preflight, cookie-дослід, CSP report-only та enforcement, headers, DOM-тести, `safe-url.js`, тести проєкту (50/50).
- Поза стендом: HTTPS і `Secure`-cookie, production-конфігурація CORS/CSP, інші браузери, CSRF/antiforgery (ЛР 6), `/scalar` та його залежності, клієнти поза `/`, `/browser-lab.html`, `/auth-lab.html`, контроль Bob.
- Нереальних PASS у документах немає; позначки `985120699e456ae0541b88aa1c457aad68be193d` та `рис. 82` потрібно замінити фактичними значеннями до подання.
