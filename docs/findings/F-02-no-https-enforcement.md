# F-02. Немає перенаправлення на HTTPS і заголовка HSTS поза Development

**Статус:** Fixed  
**Актив:** транспорт сеансу  
**Компонент:** конвеєр запитів, `Program.cs`  
**Пріоритет:** P3

## Передумови і межі огляду

Review-start `c4563b2`, fixed commit `e5cc9a9`. Production-like (`ASPNETCORE_ENVIRONMENT=Production`, `--no-launch-profile -c Release`, `http://localhost:5080`), `curl.exe`. Маршрут `GET /api/incidents` (без входу). Поза межами: реальна HTTPS-термінація й reverse proxy.

## Відтворення

1. Запустити API у Production-like режимі.
2. `curl.exe -s -D - -o NUL http://localhost:5080/api/incidents`.
3. Очікувано: перенаправлення на HTTPS. Фактично (до виправлення): 401 без `Strict-Transport-Security` і без перенаправлення.

## Вплив і ймовірність

**Статус перевірки:** оцінено за кодом і конфігурацією, поведінку спостережено локально.

Cookie сеансу й antiforgery поза Development мають `Secure`, тому прямого витоку сеансу по http немає. Проте перший запит по http не перенаправляється, а браузер не запам'ятовує вимогу HTTPS, що залишає місце для SSL stripping. Ймовірність низька, вплив низький → P3.

## Першопричина

У конвеєрі не було `UseHttpsRedirection()` і `UseHsts()`, а конфігурація не мала способу їх увімкнути.

## Виправлення

У `Program.cs` додано `AddHsts` (max-age 365 днів), `AddHttpsRedirection` (HttpsPort 443) і виклики `UseHsts()`, `UseHttpsRedirection()` за налаштуванням `Security:EnforceHttps` (за замовчуванням увімкнено поза Development). Fixed commit `e5cc9a9`, файл `Program.cs`. Для локального запуску по http: `Security__EnforceHttps=false`.

## Retest

Кроки 1–3 на `e5cc9a9`: `307 Temporary Redirect`, `Location: https://localhost/api/incidents`. Автотест `HttpsEnforcementTests` (REG-HTTPS-01): http → 307 на https; https-відповідь має `Strict-Transport-Security: max-age=31536000`.

## Positive regression

У Development за замовчуванням редиректу й HSTS немає, клієнт працює по http (`HttpsEnforcementTests.Development_DefaultsToNoRedirect_AndNoHsts`); `dotnet test` 85 з 85.

## Залишковий ризик

HTTPS-порт зафіксовано як 443 (припущення про reverse proxy); HSTS preload не вмикався. HSTS не діє на localhost за налаштуваннями ASP.NET Core, тому поведінку на https перевірено автотестом із вигаданим хостом. Реальну термінацію HTTPS не перевіряли.

## Доказ

Тест REG-HTTPS-01 (`dotnet test --filter HttpsEnforcementTests`), 85 з 85 у повному прогоні. Ручний доказ: вивід `curl.exe` до й після виправлення. Без cookie й токенів.
