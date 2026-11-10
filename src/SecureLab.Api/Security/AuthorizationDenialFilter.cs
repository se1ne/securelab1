using System.Security.Claims;
using Microsoft.AspNetCore.Http.HttpResults;

namespace SecureLab.Api.Security;

/// <summary>
/// Єдиний механізм ЛР 6 (а). Підключається до всіх захищених маршрутів інцидентів.
/// До handler: якщо subject заблоковано, повертає 429 (handler не виконується, стан не змінюється).
/// Після handler: відповідь 403 або 404 вважається відмовою й пишеться в audit.
/// Фільтрація «лише власні записи» (list/search/summary) не є відмовою: handler повертає 200.
/// Logout цей фільтр не має, тому лишається доступним.
/// </summary>
public sealed class AuthorizationDenialFilter(AuthorizationDenialTracker tracker) : IEndpointFilter
{
    public const string BurstProblemType = "https://securelab.local/problems/authorization-denied-burst";

    public async ValueTask<object?> InvokeAsync(
        EndpointFilterInvocationContext context,
        EndpointFilterDelegate next)
    {
        var http = context.HttpContext;

        var raw = http.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (!Guid.TryParse(raw, out var subject))
            return await next(context); // неавтентифікований запит не має partition

        if (tracker.GetRetryAfter(subject) is { } wait)
        {
            var seconds = (int)Math.Ceiling(wait.TotalSeconds);
            http.Response.Headers.RetryAfter = seconds.ToString(System.Globalization.CultureInfo.InvariantCulture);

            return Results.Problem(
                statusCode: StatusCodes.Status429TooManyRequests,
                type: BurstProblemType,
                title: "Забагато відмов доступу",
                detail: $"Спробуйте знову через {seconds} с.");
        }

        var result = await next(context);

        if (result is IStatusCodeHttpResult { StatusCode: StatusCodes.Status403Forbidden or StatusCodes.Status404NotFound } status)
        {
            var pattern = (http.GetEndpoint() as RouteEndpoint)?.RoutePattern.RawText ?? http.Request.Path.Value ?? "";
            var resource = http.Request.RouteValues.TryGetValue("id", out var id) && id is not null
                ? id.ToString()!
                : pattern;

            tracker.RecordDenial(
                subject,
                action: $"{http.Request.Method} {pattern}",
                resource: resource,
                statusCode: status.StatusCode!.Value,
                traceId: http.TraceIdentifier);
        }

        return result;
    }
}
