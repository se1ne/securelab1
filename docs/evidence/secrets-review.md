# Secrets review (поточні відстежувані файли)

Команди (PowerShell, `C:\dev\securelab1`):
```
git ls-files | findstr /i "appsettings .env secret key pfx"
git grep -n -iE "password|secret|apikey|token|connectionstring" -- src tests ':!*.lock.json' ':!*Migrations*'
type .gitignore
```
Межі: перевірено лише поточні відстежувані файли; історія Git і `infra/.env.example`, `appsettings.json` — див. розділ «Не перевірено / треба додати».

## Класифікація збігів

| Збіг | Файл | Висновок | Дія |
|---|---|---|---|
| Connection string із `Password=local-study-password` | `src/SecureLab.Api/appsettings.Development.json:3` | Синтетичний пароль локальної навчальної БД (127.0.0.1:54329). Не реальний секрет, але літерал у Git і шаблон, який легко скопіювати в Production | Прийнято для Development; перевірити, що Production не читає цей файл; рекомендація: брати пароль із змінної середовища |
| Той самий літерал як `LocalStudyConnectionString` | `Data/SecureLabDesignTimeDbContextFactory.cs:10` (і `infra/compose.yaml:9`) | Design-time fallback для `dotnet ef`; змінна `ConnectionStrings__SecureLab` має пріоритет | Прийнято; дублювання задокументовано |
| `SeedUsers:Password` | `Data/DbSeeder.cs:39–209` | Пароль не в Git: береться з конфігурації, без нього seed кидає помилку | Control працює |
| `Environment.GetEnvironmentVariable("SeedUsers__Password")` | `tests/**` | Те саме: пароль поза Git | Control працює |
| `"Synthetic-Wrong-1!"`, `"UpgradeTest-123!"` | `AuthenticationMechanicsTests.cs`, `PasswordHasherUpgradeTests.cs` | Явно синтетичні тестові значення, не пов'язані з акаунтами | Прийнято |
| `name="password"`, `type="password"`, `autocomplete=...`, очищення поля | `Client/auth-lab.html`, `auth-lab.js` | Правильні атрибути; значення очищується після відправлення | Control працює |
| `options.Password.RequiredLength = 10` | `Scaffolding/Lab03Identity.cs:18` | Політика, не секрет | Пов'язано з можливою finding про пароль |
| `"password"`, `"passwordHash"` у тестах відповіді | `AuthenticationMechanicsTests.cs` | Позитивна перевірка: відповідь не містить пароль чи хеш | Control працює |
| `CancellationToken`, `cancellationToken`, `ct` | `Application`, `Presentation`, `Scaffolding` | Хибні спрацьовування | Ігноруються |
| `identity_user_tokens` | `DatabaseBootstrap.cs`, `SecureLabDbContext.cs` | Назва таблиці, не токен | Ігнорується |

Реальних ключів, токенів, `.env`, `.pfx`, `.pem`, `.key` у відстежуваних файлах не знайдено.

## `.gitignore`

Покрито: `.env`, `.env.*` (крім `.env.example`), `appsettings.Local.json`, `*.pfx`, `*.pem`, `*.key`, `*.dump`, `*.sql.gz`, `*.log`, `TestResults`. Під час ЛР 6 додано `*.bundle` (локальні архіви історії, як `lab05.bundle`), тож такий файл більше не потрапить у коміт.

## Додаткові файли

- `infra/.env.example`: містить лише коментарі й `POSTGRES_PORT=54329`, секретів немає. (Нечитабельні символи в коментарях — це лише відображення UTF-8 у консолі PowerShell.)
- `src/SecureLab.Api/appsettings.json`: connection string і паролів немає. Помічено `AllowedHosts: "*"` і рівень `Microsoft.EntityFrameworkCore.Database.Command: Information` (EF пише SQL у журнал; перевірити в огляді логів, етап 3).
- Історія Git: `git log --all --oneline -S"local-study-password"` дає один commit `0992246 Import starter baseline 2-A`. Літерал прийшов зі стартового baseline, пізніше не змінювався. Інші секрети в історії не шукалися (межа огляду: лише цей рядок).
- `infra/compose.yaml:9`: `POSTGRES_PASSWORD: local-study-password`. Те саме синтетичне значення, що в `appsettings.Development.json` і design-time factory (всього три місця). Це пароль локальної БД у Docker Compose; прийнято як навчальний, у Production такий пароль використовувати не можна.

## Перевірка журналів на секрети (етап 3)

- Production-like запуск із усіма сценаріями: пошук `SeedUsers__Password` у повному журналі, пошук рядка `Set-Cookie`/значення cookie, пошук значення antiforgery token: 0 збігів у кожному випадку.
- Автотести: `AuthorizationDenialBurstTests` (записи аудиту не містять пароля), `LoginLoggingTests` (журнал входу не містить ні введеного імені, ні пароля при невдачі; REG-LOG-01).
- EF Core логує SQL (`Database.Command: Information`), але значення параметрів маскуються як `'?'`, тобто чутливі дані не потрапляють у журнал. `EnableSensitiveDataLogging` не вмикався.
- Журнал входу раніше містив введене ім'я (F-01): виправлено, див. `docs/findings/F-01-login-log-raw-username.md`.

## Не перевірено

- Історія Git шукалася лише за рядком `local-study-password`; інші секрети в давніх комітах не шукалися.
- Сторонні пакети: перевірено лише відомі вразливості (`dotnet package list --vulnerable --include-transitive`), не зміст пакетів.
- Docker-образи й змінні середовища на машині розробника не оглядалися.
