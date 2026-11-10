# Власна карта source-to-sink (DEL-01)

Рівень: **відмінний («Відмінно»)**. Спільний сценарій 2-A.
Стан/commit: vulnerable `84697d859d696371ec5b1b0ef7a4cf83b17bea08` (scaffold `lab-05-start-v1`), fixed — `d15159f` (safe DOM), кінцевий — `<FINAL_COMMIT>`.
Вхід/Guid записів: marker-запис Alice `b4285b47-81b4-4bac-aa5e-e3bfe1553647`; seed-інцидент Alice `20000000-0000-0000-0000-000000000001`; запис для DOM-тесту `6dade752-233c-4aa4-877d-3f44ad6612d3`.
Класифікація: **stored XSS** (значення збережено в БД і виконалося при пізнішому перегляді іншим користувачем) через **DOM-sink** на клієнті (`innerHTML`). Reflected XSS у scope не входить.

## Потік 1. Incident.Description

| Крок | Файл та функція/DTO | Конкретне поле/значення | Доказ і довіра |
|---|---|---|---|
| Source | `Client/browser-lab.html`, `form#edit`, `<textarea name="description">` | harmless marker із `resources/lab05-marker.txt` | рис. 10; контрольоване користувачем |
| Request | `Client/browser-lab.js`, submit-handler форми: `fetch("/api/incidents", POST)` | JSON-поле `description` у тілі разом із `title`, `severity: "Low"`, `occurredAtUtc` | рис. 12 (Network, POST 201, payload); контрольоване користувачем |
| Validation/mapping | обробник `POST /api/incidents` (`Scaffolding/Lab02Endpoints.cs`, створення incident; перевірити точний файл командою `git grep -n 'MapPost("/api/incidents"' -- src`) | обов'язковість, `Trim`, довжина, `description ≠ title` (правила ЛР 2); `id`, власника, статус і час ставить сервер | `<`, `>`, лапки не відхиляються: Description — звичайний текст; validation не робить значення безпечним для HTML |
| Storage | сутність `Incident.Description`, таблиця інцидентів у PostgreSQL | те саме значення, що й у payload (marker символ у символ) | збережене значення користувача; рис. 12 і 20–22 (той самий запис до й після fix) |
| Response | `Application/Incidents/IncidentQueries.cs`, `GetDetailsAsync` → `Presentation/Contracts`, `IncidentDetailsResponse.Description` | JSON-поле `description` у `GET /api/incidents/{id}` | рис. 12; JSON-екранування лапок (`\"`) — це запис JSON, а не захист HTML |
| Client transform | `Client/browser-lab.js`, `load()` | `current = await response.json()`; без перетворень | значення лишається недовіреним для відображення |
| Sink/context | `Client/browser-lab.js`, `load()`, елемент `#description` | **було** (рядок 10): `innerHTML = current.description` → HTML-контекст; **стало**: `replaceChildren(document.createTextNode(current.description))` → текстовий вузол | рис. 11, 15–17 (до); рис. 20–25 (після) |

Висновок по потоку: сервер повертає недовірений текст без змін, а виправлення зроблено саме в sink. Збережене значення й API response не змінювалися.

## Потік 2. IncidentComment.Text (Добре / Відмінно)

| Крок | Файл та функція/DTO | Конкретне поле/значення | Доказ і довіра |
|---|---|---|---|
| Source | `Data/DbSeeder.cs`, `SeedAsync`, константа `Lab05Marker` | публічний коментар `30000000-0000-0000-0000-000000000005`, автор Morgan, `IsInternal = false`, інцидент Alice | рис. 27–29 (commit `f77b21d`); у продукті ним був би автор коментаря |
| Request | endpoint створення коментаря в API відсутній | seed замінює request | рис. 27 |
| Validation/mapping | відсутні (службовий код seed) | — | значення не очищується |
| Storage | сутність `IncidentComment.Text`, таблиця коментарів | `<img src=x onerror="…">` | збережене значення без змін |
| Response | `IncidentQueries.GetDetailsAsync`: `Comments.Where(!IsInternal).OrderBy(CreatedAtUtc)` → `IncidentCommentResponse(Id, AuthorDisplayName, Text, CreatedAtUtc)` | JSON `comments[].text` | рис. 35 (до), рис. 93 (після): значення однакове |
| Client transform | `Client/browser-lab.js`, `load()`, цикл `for (const comment of current.comments ?? [])` | `comment.text` | без перетворень |
| Sink/context | `Client/browser-lab.js`, `load()`, елемент `<p>` у `#comments` | **було** (рядок 14): `paragraph.innerHTML = comment.text`; **стало**: `createTextElement("p", comment.text)` (`textContent`) | рис. 30–34 (до: `<img>` і `executed`); рис. 36–37 (після: текст) |

## Поглиблена перевірка (Відмінно)

| Перевірка | Файл/команда | Vulnerable `84697d8` | Fixed | Доказ |
|---|---|---|---|---|
| Опис як текстовий вузол | `tests/browser/description-dom.js` (Console, `/browser-lab.html`) | FAIL: `Text changed` | PASS | рис. 82, 84 (FAIL); PASS — рис. 82 |
| Коментарі, повторний render без дублювання | `tests/browser/comments-dom.js` | FAIL: `Comment 1: text changed` | PASS: `every comment rendered as plain text, no duplicates after re-render` | рис. 87–88 |
| Позитивні рядки | форма `/browser-lab.html` | — | `5 < 7`, `9 > 3`, лапки, апостроф, `&`, кирилиця, 日本語, емодзі відображено без пошкоджень; 3900 символів без помилок | рис. 26, 90, 91 |
| URL-контекст | `resources/copyable/safe-url.js` (нейтральний приклад) | — | `javascript:` та некоректні значення → `null`; `/incidents/1` → `http://localhost:5080/incidents/1`; `onclick` відсутній | рис. 92 |

Під CSP enforcement браузер блокує inline-обробник (`script-src-attr`) і на vulnerable-коді, але елемент `<img>` усе одно створюється — тест це ловить (рис. 82, 88). Тому висновок «sink виправлено» зроблено за DOM, а не за відсутністю виконання marker.

## Інвентаризація DOM-sinks

| Файл / функція | Категорія даних | Контекст | Рішення |
|---|---|---|---|
| `browser-lab.js`, `load()`, `#title` | `title` з API | текстовий вузол (`textContent`) | безпечно з початку |
| `browser-lab.js`, `load()`, `#description` | `description` з API | **HTML** (`innerHTML`) | **виправлено**: текстовий вузол (`d15159f`) |
| `browser-lab.js`, `load()`, `#comments` | `comments[].text` з API | **HTML** (`innerHTML`) | **виправлено**: `createTextElement("p", …)` (`d15159f`) |
| `browser-lab.js`, `load()`, `elements.description.value` | `description` з API | значення поля форми (властивість `value`) | безпечно: `value` не розбирається як HTML |
| `browser-lab.js`, `#status` | статус HTTP | текстовий вузол | безпечно |
| `Client/app.js`, `createTextElement` (основний клієнт `/`) | поля інцидентів | `textContent` | безпечно за зразком Title; поля, окрім `title`, у цій роботі окремо не досліджувалися |

Усі sinks, у яких значення з API потрапляло в HTML-парсер, замінено. Нових вразливостей у застосунок не додавалося.

## Залишковий ризик

- Інші клієнти та сторінки, окрім `browser-lab.html` і досліджених полів `app.js`, не перевірялися.
- Нове поле з HTML-контекстом без safe DOM API знову стане sink: CSP лише зменшує наслідки.
- Сторінка `/scalar` у Development виключена з CSP (сторонній UI-пакет); у production її немає.
- Сторонніх скриптів у досліджених сторінках немає (`default-src 'self'`).
