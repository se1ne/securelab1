# Звіт до лабораторної роботи № TODO

## 1. Ідентифікація стану

- Варіант: 2-A «Трекер інцидентів».
- Гілка: lab/1-system.
- Фінальний тег: `v0.1.0`.
- Commit hash: `TODO`.

## 2. Змінений маршрут

1. Client (`app.js`): Подія `click` на кнопці запускає `loadSeveritySummary()`, який виконує `apiFetch('/api/incidents/severity-summary')`.
2. Presentation (`IncidentEndpoints.cs`): Маршрут `GET /api/incidents/severity-summary` викликає метод `GetSeveritySummaryAsync`.
3. Application (`IncidentQueries.cs`): Метод `GetSeveritySummaryAsync` виконує асинхронний LINQ-запит із `AsNoTracking()`, групує дані за `Severity`, доповнює відсутні рівні значеннями `Count: 0` (політика повного переліку) та формує результат у спадному порядку критичності (`Critical` → `Low`).
4. Data & DB: EF Core надсилає SQL-запит із `GROUP BY` до таблиці `incidents` у PostgreSQL.
5. Response & DOM: Повертається список `IncidentSeveritySummaryResponse` у JSON. `app.js` через `textContent` безпечно оновлює елементи списку та статус.

## 3. Виконані зміни

1. Реалізовано контракт `IncidentSeveritySummaryResponse(string Severity, int Count)` у `Presentation/Contracts/IncidentResponses.cs`.
2. Написано метод `GetSeveritySummaryAsync` у `IncidentQueries.cs` із підтримкою повного переліку enum, явного сортування, структурованого логування та фіксації `TraceId`.
3. Замінено заглушку `501 Not Implemented` на повноцінний endpoint у `IncidentEndpoints.cs`.
4. Оновлено фронтенд (`index.html` та `app.js`): додано кнопку, список та елемент статусу `<p id="summary-status" role="status">`.
5. Додано документацію контракту в `tests/http/incidents.http` та написано інтеграційний тест у `SecureLab.Api.Tests`.
6. Змінено випадковий шлях з 200 з HTML, на 404 з Problem Details.

## 4. Перевірка

| ID | Передумови | Дія | Очікувано | Фактично | Доказ |
|---|---|---|---|---|---|
| T-01 | Сервер запущено | `curl.exe -i http://localhost:5080/api/incidents` | HTTP 200 OK, JSON-масив інцидентів | HTTP 200 OK, JSON-масив з інцидентами | Рисунок 17 |
| T-02 | Сервер запущено | `curl.exe -i http://localhost:5080/api/incidents/severity-summary` | HTTP 200 OK, масив 4 рівнів (Critical:0, High:1, Medium:1, Low:1) | HTTP 200 OK, масив у порядку Critical..Low | Рисунок 57 |
| T-03 | Сервер запущено | `curl.exe -i http://localhost:5080/api/incidents/20000000-0000-0000-0000-000000000003` (існуючий) | HTTP 200 OK, деталі інциденту | HTTP 200 OK, об'єкт інциденту | Рисунок 27 |
| T-04 | Сервер запущено | `curl.exe -i http://localhost:5080/api/incidents/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa` | HTTP 404 Not Found, Problem Details із `traceId` | HTTP 404, містить `traceId` | Рисунок 66 |
| T-05 | Сервер запущено | `curl.exe -i http://localhost:5080/api/incidents?status=Unknown` | HTTP 400 Bad Request,  `traceId`, One or more validation errors occurred. | HTTP 400, містить `traceId`, One or more validation errors occurred. | Рисунок 65 |
| T-06 | Сервер запущено | `curl.exe -i http://localhost:5080/api/incidents?status=Resolved` | HTTP 200 OK, [] | HTTP 200, містить [] | Рисунок 65 |
| T-07 | Відкрито UI у браузері | Клік на кнопку "Оновити підсумок" | Завантаження даних, вивід 4 карт підсумку | Відображено 4 рівні з відповідною кількістю | Рисунок 55 |
| T-08 | Запущено тестувальне середовище | Виконання `dotnet test` | succeeded: 5 | succeeded: 5 | Рисунок 69 |
| T-09 | Сервер запущено | Виконання `GET /api/unknown` | 404, Problem | 404, Problem | Рисунок 71 |

## 5. Security-сценарій

Для ЛР1 навмисно вразливого стану немає.

## 6. Висновок

У ході виконання лабораторної роботи № 1 було успішно реалізовано наскрізне розширення системи: додано endpoint підсумку інцидентів за рівнем критичності (`/api/incidents/severity-summary`). Забезпечено дотримання правил меж довіри (структуроване DTO, безпечне відображення в DOM, валідація), реалізовано структуроване логування та наскрізну кореляцію запитів за допомогою `TraceId`. Усі автоматичні та ручні тести пройдено успішно.
