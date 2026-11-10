using Microsoft.AspNetCore.Antiforgery;

namespace SecureLab.Api.Security;

/// <summary>Контракт між сервером і клієнтом: назва header і маршрут видачі токена.</summary>
public static class AntiforgeryContract
{
    public const string HeaderName = "X-CSRF-TOKEN";
    public const string TokenRoute = "/api/auth/csrf-token";
    public const string ProblemType = "https://securelab.local/problems/antiforgery";
}

/// <summary>
/// Єдине місце, де викликається ValidateRequestAsync (explicit validation).
/// AntiforgeryValidationException перетворюється на один точний 400 Problem Details.
/// Підключається лише до cookie-authenticated mutation-маршрутів (не до GET).
/// </summary>
public sealed class AntiforgeryValidationFilter(IAntiforgery antiforgery) : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(
        EndpointFilterInvocationContext context,
        EndpointFilterDelegate next)
    {
        try
        {
            await antiforgery.ValidateRequestAsync(context.HttpContext);
        }
        catch (AntiforgeryValidationException)
        {
            return Results.Problem(
                statusCode: StatusCodes.Status400BadRequest,
                type: AntiforgeryContract.ProblemType,
                title: "Antiforgery token is missing or invalid.");
        }

        return await next(context);
    }
}

public static class AntiforgeryEndpoints
{
    /// <summary>Same-origin маршрут видачі request token; потребує входу (токен прив'язаний до користувача).</summary>
    public static IEndpointRouteBuilder MapCsrfToken(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet(AntiforgeryContract.TokenRoute, (HttpContext httpContext, IAntiforgery antiforgery) =>
            {
                var tokens = antiforgery.GetAndStoreTokens(httpContext);
                httpContext.Response.Headers.CacheControl = "no-store";
                return Results.Ok(new
                {
                    headerName = AntiforgeryContract.HeaderName,
                    token = tokens.RequestToken
                });
            })
            .RequireAuthorization()
            .WithName("GetCsrfToken");

        return endpoints;
    }
}
