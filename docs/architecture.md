# Карта архітектури

Це початкова карта. Під час ЛР 1 доповніть її власним трасуванням запиту,
конкретними файлами та спостереженнями з DevTools і журналу PostgreSQL.

## Компоненти

| Компонент | Розташування | Відповідальність |
|---|---|---|
| Browser client | `src/SecureLab.Api/Client/` | Надсилає HTTP-запити, безпечно показує відповідь через DOM API |
| Presentation | `Presentation/` | Описує endpoints, читає зовнішні параметри, формує HTTP-відповідь |
| Application | `Application/` | Виконує сценарії отримання списку, деталей інциденту та підсумку (summary) за рівнем критичності |
| Data | `Data/` | Відображає C#-сутності на PostgreSQL через EF Core/Npgsql |
| PostgreSQL | `infra/compose.yaml` | Зберігає навчальні дані у локальному контейнері |

## Підготовлений наскрізний маршрут

```text
severity-summary (кнопка -> app.js -> GET /api/incidents/severity-summary -> IncidentEndpoints -> IncidentQueries -> SecureLabDbContext.Incidents / таблиця incidents -> IncidentSeveritySummaryResponse -> textContent);
```

## Межі довіри

Доповніть таблицю щонайменше трьома конкретними спостереженнями.

| Межа | Чому даним ще не можна довіряти | Де перевіряємо або обмежуємо |
|---|---|---|
| Користувач → Browser client | Користувач контролює введення | Форми та елементи UI (первинна валідація, але фронтенд не є єдиним контролем) |
| Browser client → API | Клієнт і HTTP-запит можна змінити поза UI | Обмеження маршруту за допомогою guid, параметризовані SQL-запити в EF Core |
| PostgreSQL → API → DOM | У БД може зберігатися раніше введений недовірений текст | DTO та безпечний DOM sink; таблиці з рівнями критичності може не бути; DTO обмежує поля, а DOM отримує текст через textContent; |

## Конфігураційні входи

- `global.json` — версія .NET SDK;
- `src/SecureLab.Api/appsettings*.json` — режим міграцій і локальний connection string;
- `infra/compose.yaml` — версія PostgreSQL, порт і локальні навчальні облікові дані;
- змінна середовища `ConnectionStrings__SecureLab` — безпечний спосіб перевизначити connection string поза репозиторієм.
- спосіб повернення до seed - dotnet run --project src/SecureLab.Api -- --reset-database
