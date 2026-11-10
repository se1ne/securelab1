using System.Security.Claims;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;

namespace SecureLab.Api.Security;

/// <summary>
/// Limiter для GET /api/incidents/search.
/// Ключ partition: id автентифікованого користувача (identity, а не значення від клієнта).
/// UseRateLimiter() стоїть після UseAuthentication/UseAuthorization, тому User уже відомий.
/// Rate limit не замінює authorization: він лише обмежує частоту запитів.
/// </summary>
public static class SearchRateLimit
{
    public const string PolicyName = "search";
    public const int PermitLimit = 20;
    public static readonly TimeSpan Window = TimeSpan.FromSeconds(10);

    public static RateLimiterOptions AddSearchPolicy(this RateLimiterOptions options)
    {
        options.AddPolicy(PolicyName, httpContext =>
        {
            var key = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "anonymous";

            return RateLimitPartition.GetFixedWindowLimiter(
                partitionKey: key,
                factory: _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = PermitLimit,
                    Window = Window,
                    QueueLimit = 0,
                    AutoReplenishment = true
                });
        });
        return options;
    }
}
