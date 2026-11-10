using System.Security.Claims;

namespace SecureLab.Api.Security;

/// <summary>
/// Audit привілейованої дії (triage): після успішного виконання пише запис категорії "Audit".
/// Хто (subject), що (action), над чим (resource), результат, час, traceId. Тіло запиту та секрети не логуються.
/// </summary>
public sealed class PrivilegedActionAuditFilter(ILoggerFactory loggerFactory, TimeProvider time) : IEndpointFilter
{
    public const string EventType = "incident.triaged";

    private readonly ILogger _audit = loggerFactory.CreateLogger("Audit");

    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var result = await next(context);

        var http = context.HttpContext;
        if (result is IStatusCodeHttpResult { StatusCode: >= 200 and < 300 }
            && Guid.TryParse(http.User.FindFirst(ClaimTypes.NameIdentifier)?.Value, out var subject))
        {
            var pattern = (http.GetEndpoint() as RouteEndpoint)?.RoutePattern.RawText ?? http.Request.Path.Value ?? "";
            var resource = http.Request.RouteValues.TryGetValue("id", out var id) && id is not null
                ? id.ToString()! : pattern;

            _audit.LogInformation(
                "Audit {EventType}: subject {Subject}, action {Action}, resource {Resource}, result {Result}, time {Time}, traceId {TraceId}",
                EventType, subject, $"{http.Request.Method} {pattern}", resource, "success",
                time.GetUtcNow(), http.TraceIdentifier);
        }

        return result;
    }
}
