# F-03. Привілейована зміна статусу (triage) не лишає запису аудиту

**Статус:** Fixed  
**Актив:** привілейований перехід triage, дані аудиту  
**Компонент:** `POST /api/incidents/{id}/triage`, `Presentation/Endpoints/IncidentEndpoints.cs`  
**Пріоритет:** P2

## Передумови і межі огляду

Review-start `c4563b2`, fixed commit `e5cc9a9`. Development, Firefox 159, база з seed-даними. Користувач morgan (Analyst), інцидент зі статусом New. Маршрут `POST /api/incidents/{id}/triage`. Поза межами: централізоване сховище журналів.

## Відтворення

1. Увійти як morgan на `auth-lab.html`.
2. У консолі: `(await window.csrf.fetch('/api/incidents/{id}/triage',{method:'POST'})).status` для інциденту зі статусом New.
3. Подивитися журнал сервера. Очікувано: запис про те, хто, коли й над яким інцидентом виконав triage. Фактично (до виправлення): 204, у журналі лише SQL `UPDATE incidents SET status = @p0, updated_at_utc = @p1`, запису категорії `Audit` немає.

## Вплив і ймовірність

**Статус перевірки:** спостережено локально.

Якщо статус змінено помилково або недобросовісно, за журналом не можна встановити виконавця, час і ресурс. Дія захищена (роль, antiforgery, 409 на повторі), тому порушується можливість розслідування, а не доступ. Сценарій повторюється при кожному triage → вплив середній, ймовірність висока → P2.

## Першопричина

Для маршруту triage не було жодного audit-логування: handler змінює статус і повертає 204, а `ILogger` фіксує лише діагностику EF Core.

## Виправлення

Додано `PrivilegedActionAuditFilter`: після успішної відповіді (2xx) пише запис категорії `Audit`: `incident.triaged`, subject, action, resource, result, time, traceId. Невдалі спроби (403, 404, 409) цей запис не створюють: відмови фіксує `AuthorizationDenialFilter`. Фільтр підключено до маршруту triage після `AntiforgeryValidationFilter`. Fixed commit `e5cc9a9`, файли `Security/PrivilegedActionAuditFilter.cs`, `IncidentEndpoints.cs`.

## Retest

Кроки 1–3 на `e5cc9a9` для іншого інциденту зі статусом New: 204, у журналі `Audit incident.triaged: subject …, action POST /api/incidents/{id:guid}/triage, resource …, result success, time …, traceId …`. Автотест `TriageAuditTests` (REG-AUDIT-01): успішний triage дає один запис із усіма полями.

## Positive regression

Triage аналітика й далі повертає 204 і змінює статус; повторний triage дає 409 без нового audit-запису; Reporter отримує 403 без запису про triage (`TriageAuditTests`, `IncidentEndpointTests.A06/A07/Triage_*`).

## Залишковий ризик

Журнал лишається в консолі процесу без захисту від зміни й сповіщень. Запис не містить попереднього й нового значення статусу, лише факт переходу й ресурс.

## Доказ

Тест REG-AUDIT-01 (`dotnet test --filter TriageAuditTests`), 85 з 85 у повному прогоні. Ручний доказ: консоль (204) і рядок журналу до й після виправлення. Без cookie й токенів.
