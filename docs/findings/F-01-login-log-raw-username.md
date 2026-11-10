# F-01. Журнал входу записує введене ім'я користувача як є

**Статус:** Fixed  
**Актив:** журнали, облікові дані  
**Компонент:** `POST /api/auth/login`, `Scaffolding/Lab03Identity.cs`  
**Пріоритет:** P3

## Передумови і межі огляду

Review-start `c4563b2`, fixed commit `e5cc9a9`. Development, Firefox 159, база з seed-даними (скидання: `$env:Database__AllowReset="true"; dotnet run --project src/SecureLab.Api -- --reset-database`). Користувач alice (пароль із `SeedUsers__Password` поза Git). Маршрут `POST /api/auth/login`. Поза межами: решта журналів, централізоване сховище.

## Відтворення

1. Запустити API (Development).
2. На `auth-lab.html` у консолі: `fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({userName:'nobody-user-123',password:'wrong-pass-123'})})`.
3. Очікувано: 401 і запис журналу без введеного тексту. Фактично (до виправлення): 401, у журналі `Authentication event login: user nobody-user-123, result failure, trace …`.

## Вплив і ймовірність

**Статус перевірки:** спостережено локально.

Користувач може помилково ввести пароль у поле імені, і пароль потрапить у журнал; довільний рядок із керуючими символами або дуже довгий потрапляє в журнал без обмежень. Сценарій доступний будь-кому, хто може викликати login; ймовірність середня, вплив низький → P3. CVSS не оцінювався.

## Першопричина

Обробник входу передавав `input.UserName` у `logger.LogInformation` для всіх результатів, включно з невдалими, без жодної обробки.

## Виправлення

Додано `LogSanitizer.Fingerprint` (`sha256:` + перші 8 hex SHA-256 нормалізованого імені). При невдалому вході та порожніх даних у журнал іде лише `userRef`; при успішному вході пишеться ім'я підтвердженого користувача. Fixed commit `e5cc9a9`, файли `Scaffolding/Lab03Identity.cs`, `Security/LogSanitizer.cs`.

## Retest

Кроки 1–3 на `e5cc9a9`: 401, у журналі `Authentication event login: userRef sha256:70803aed, result failure, trace …`, введеного імені немає. Автотест `LoginLoggingTests` (REG-LOG-01): для невідомого імені, існуючого імені з хибним паролем і пароля, введеного в поле імені, жоден запис журналу не містить введеного тексту.

## Positive regression

Успішний вхід alice: 204, у журналі `user alice, result success`, пароля немає; `LoginLoggingTests.SuccessfulLogin_LogsVerifiedUser_WithoutPassword`; `AuthenticationMechanicsTests` проходять.

## Залишковий ризик

Відбиток короткого імені можна підібрати перебором, якщо відомий журнал. Мета — не зберігати введений текст, а не приховати існування імені від того, хто має журнал. Журнали лишаються в консолі процесу.

## Доказ

Тест REG-LOG-01 (`dotnet test --filter LoginLoggingTests`), 85 з 85 у повному прогоні. Ручний доказ: консоль браузера (401) і рядок журналу до й після виправлення. Пароль, cookie і токени на доказах відсутні.
