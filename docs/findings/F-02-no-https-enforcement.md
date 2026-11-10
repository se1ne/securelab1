# F-02. Немає перенаправлення на HTTPS і заголовка HSTS поза Development

| Поле | Значення |
|---|---|
| Ідентифікатор | F-02 |
| Тип | Недостатній захист транспорту (A02:2021 / A05:2021, CWE-319) |
| Серйозність | Low |
| Компонент | Конвеєр запитів (Program.cs) |
| Статус | Виправлено, повторна перевірка пройдена |

## Опис

Cookie сеансу й antiforgery поза Development мають `Secure`, але сам застосунок не перенаправляв HTTP на HTTPS і не надсилав `Strict-Transport-Security`. Користувач, який відкрив адресу по http, не отримував вказівки перейти на HTTPS, а браузер не запам'ятовував вимогу використовувати HTTPS.

## Як виявлено

Production-like запуск і запит `curl -s -D - -o NUL http://localhost:5080/api/incidents` → 401 без `Strict-Transport-Security` і без перенаправлення (рисунок 80).

## Ризик

Перший запит по http можна перехопити чи підмінити (SSL stripping), доки клієнт не перейшов на HTTPS. Ризик обмежений: cookie з `Secure` по http не передається, тому прямого витоку сеансу немає.

## Виправлення

У `Program.cs` додано `AddHsts` (max-age 365 днів) і `AddHttpsRedirection` (HttpsPort 443), а в конвеєр `UseHsts()` і `UseHttpsRedirection()`. Режим керується налаштуванням `Security:EnforceHttps`: за замовчуванням увімкнений поза Development, у Development вимкнений. Для локального запуску по http: `Security__EnforceHttps=false`.

## Повторна перевірка

1. Автоматично: `HttpsEnforcementTests` (REG-HTTPS-01): http → 307 на https; https-відповідь має `Strict-Transport-Security: max-age=31536000`; у Development за замовчуванням редиректу й HSTS немає. 85 тестів з 85 (рисунок 86).
2. Вручну: Production-like, той самий запит → `307 Temporary Redirect`, `Location: https://localhost/api/incidents` (рисунок 89).

## Залишковий ризик

HTTPS-порт зафіксовано як 443 (зовнішній порт за reverse proxy). HSTS preload не вмикався. HSTS не діє на localhost за налаштуваннями ASP.NET Core, тому повну поведінку на https перевірено автотестом із вигаданим хостом.
