using System.Security.Claims;
using SecureLab.Api.Data;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Presentation.Endpoints;

public static class IncidentEndpoints
{
    public static IEndpointRouteBuilder MapIncidentEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/api/incidents")
            .WithTags("Incidents");

        group.MapGet("/", GetListAsync)
            .WithName("GetIncidents")
            .Produces<IReadOnlyList<IncidentListItemResponse>>()
            .ProducesValidationProblem();

        group.MapGet("/{id:guid}", GetDetailsAsync)
            .RequireAuthorization()
            .WithName("GetIncidentDetails")
            .Produces<IncidentDetailsResponse>()
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status404NotFound);

        group.MapGet("/severity-summary", GetSeveritySummaryAsync)
            .WithName("GetIncidentSeveritySummary")
            .Produces<IReadOnlyList<IncidentSeveritySummaryResponse>>();

        group.MapPut("/{id:guid}", UpdateContentAsync)
            .RequireAuthorization()
            .WithName("UpdateIncidentContent")
            .Produces<IncidentDetailsResponse>()
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status404NotFound);

        return endpoints;
    }

    private static async Task<IResult> GetListAsync(
        string? status,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        IncidentStatus? parsedStatus = null;
        if (status is not null)
        {
            if (!Enum.TryParse<IncidentStatus>(status, ignoreCase: true, out var candidate)
                || !Enum.IsDefined(candidate))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["status"] = ["Допустимі значення: New, Triaged, InProgress, Resolved, Closed."]
                });
            }

            parsedStatus = candidate;
        }

        return Results.Ok(await queries.GetListAsync(parsedStatus, cancellationToken));
    }

    private static async Task<IResult> GetDetailsAsync(
        Guid id,
        HttpContext httpContext,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        var userIdValue = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (!Guid.TryParse(userIdValue, out var userId))
        {
            return Results.Problem(
                statusCode: StatusCodes.Status500InternalServerError,
                title: "Authenticated user identifier is invalid.");
        }

        var isPrivilegedReader = httpContext.User.IsInRole(DbSeeder.AnalystRole);

        var incident = await queries.GetDetailsAsync(id, userId, isPrivilegedReader, cancellationToken);
        return incident is null
            ? Results.Problem(
                title: "Інцидент не знайдено",
                detail: $"Інцидент '{id}' не існує.",
                statusCode: StatusCodes.Status404NotFound)
            : Results.Ok(incident);
    }

    private static async Task<IResult> UpdateContentAsync(
        Guid id,
        UpdateIncidentRequest request,
        HttpContext httpContext,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        var userIdValue = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (!Guid.TryParse(userIdValue, out var userId))
        {
            return Results.Problem(
                statusCode: StatusCodes.Status500InternalServerError,
                title: "Authenticated user identifier is invalid.");
        }

        var now = DateTimeOffset.UtcNow;
        var errors = new Dictionary<string, string[]>();

        if (string.IsNullOrWhiteSpace(request.Title))
            errors["title"] = ["Тема обов'язкова."];
        else if (request.Title.Length > 160)
            errors["title"] = ["Тема не довша за 160 символів."];

        if (string.IsNullOrWhiteSpace(request.Description))
            errors["description"] = ["Опис обов'язковий."];
        else if (request.Description.Length > 4000)
            errors["description"] = ["Опис не довший за 4000 символів."];

        var severityIsValid =
            Enum.TryParse<IncidentSeverity>(request.Severity, ignoreCase: true, out var severity)
            && Enum.IsDefined(severity);
        if (!severityIsValid)
            errors["severity"] = ["Допустимі значення: Low, Medium, High, Critical."];

        if (request.OccurredAtUtc is null)
            errors["occurredAtUtc"] = ["Час настання обов'язковий."];
        else if (request.OccurredAtUtc > now.AddMinutes(5))
            errors["occurredAtUtc"] = ["Час настання не може випереджати поточний час більш ніж на 5 хвилин."];

        var title = request.Title?.Trim() ?? "";
        var description = request.Description?.Trim() ?? "";

        if (severityIsValid
            && (severity == IncidentSeverity.High || severity == IncidentSeverity.Critical)
            && !errors.ContainsKey("description")
            && description.Length < 40)
            errors["description"] = ["Для High або Critical опис має містити щонайменше 40 символів."];

        if (errors.Count > 0)
            return Results.ValidationProblem(errors);

        var occurredAtUtc = request.OccurredAtUtc!.Value.ToUniversalTime();

        var updated = await queries.UpdateContentAsync(
            id, userId, title, description, severity, occurredAtUtc, cancellationToken);

        return updated is null
            ? Results.Problem(
                title: "Інцидент не знайдено",
                detail: $"Інцидент '{id}' не існує.",
                statusCode: StatusCodes.Status404NotFound)
            : Results.Ok(updated);
    }

    private static async Task<IResult> GetSeveritySummaryAsync(IncidentQueries queries, CancellationToken cancellationToken)
    {
        var summary = await queries.GetSeveritySummaryAsync(cancellationToken);
        return Results.Ok(summary);
    }
}