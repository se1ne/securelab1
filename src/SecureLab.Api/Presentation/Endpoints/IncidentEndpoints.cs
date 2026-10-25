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
             
        endpoints.MapGet("/api/incident-comments/{id:guid}", GetCommentAsync)
            .RequireAuthorization()
            .WithName("GetIncidentComment")
            .Produces<IncidentCommentDetailsResponse>()
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound);
        
        var group = endpoints.MapGroup("/api/incidents")
            .WithTags("Incidents");

        group.MapGet("/", GetListAsync)
            .RequireAuthorization()
            .WithName("GetIncidents")
            .Produces<IReadOnlyList<IncidentListItemResponse>>()
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status403Forbidden);

        group.MapGet("/{id:guid}", GetDetailsAsync)
            .RequireAuthorization()
            .WithName("GetIncidentDetails")
            .Produces<IncidentDetailsResponse>()
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status404NotFound);

        group.MapGet("/severity-summary", GetSeveritySummaryAsync)
            .RequireAuthorization()
            .WithName("GetIncidentSeveritySummary")
            .Produces<IReadOnlyList<IncidentSeveritySummaryResponse>>()
            .ProducesProblem(StatusCodes.Status403Forbidden);

        group.MapPut("/{id:guid}", UpdateContentAsync)
            .RequireAuthorization()
            .WithName("UpdateIncidentContent")
            .Produces<IncidentDetailsResponse>()
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status404NotFound);
        
        group.MapDelete("/{id:guid}", DeleteAsync)
            .RequireAuthorization()
            .WithName("DeleteIncident")
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status404NotFound);

        group.MapPost("/{id:guid}/triage", TriageAsync)
            .RequireAuthorization()
            .WithName("TriageIncident")
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status409Conflict);

        return endpoints;
    }

   

    private static async Task<IResult> GetListAsync(
        string? status,
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

        var isAnalyst = httpContext.User.IsInRole(DbSeeder.AnalystRole);
        var isReporter = httpContext.User.IsInRole(DbSeeder.ReporterRole);

        if (!isAnalyst && !isReporter)
        {
            return Results.Problem(
                statusCode: StatusCodes.Status403Forbidden,
                title: "Доступ заборонено для цієї ролі.");
        }

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

        var ownerFilter = isAnalyst ? null : (Guid?)userId;

        return Results.Ok(await queries.GetListAsync(parsedStatus, ownerFilter, cancellationToken));
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

    private static async Task<IResult> DeleteAsync(
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

        var deleted = await queries.DeleteAsync(id, userId, cancellationToken);

        return deleted
            ? Results.NoContent()
            : Results.Problem(
                title: "Інцидент не знайдено",
                detail: $"Інцидент '{id}' не існує.",
                statusCode: StatusCodes.Status404NotFound);
    }

    private static async Task<IResult> TriageAsync(
        Guid id,
        HttpContext httpContext,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        if (!httpContext.User.IsInRole(DbSeeder.AnalystRole))
        {
            return Results.Problem(
                statusCode: StatusCodes.Status403Forbidden,
                title: "Лише Analyst може виконувати цю дію.");
        }

        var result = await queries.TriageAsync(id, cancellationToken);

        return result switch
        {
            TriageResult.Success => Results.NoContent(),
            TriageResult.NotFound => Results.Problem(
                title: "Інцидент не знайдено",
                detail: $"Інцидент '{id}' не існує.",
                statusCode: StatusCodes.Status404NotFound),
            TriageResult.InvalidTransition => Results.Problem(
                title: "Перехід неможливий",
                detail: "Перевести в Triaged можна лише інцидент у стані New.",
                statusCode: StatusCodes.Status409Conflict),
            _ => Results.Problem(statusCode: StatusCodes.Status500InternalServerError)
        };
    }

    private static async Task<IResult> GetCommentAsync(
        Guid id,
        HttpContext httpContext,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        if (!httpContext.User.IsInRole(DbSeeder.AnalystRole))
        {
            return Results.Problem(
                statusCode: StatusCodes.Status403Forbidden,
                title: "Доступ до внутрішніх коментарів дозволений лише Analyst.");
        }

        var comment = await queries.GetCommentAsync(id, cancellationToken);

        return comment is null
            ? Results.Problem(
                title: "Коментар не знайдено",
                detail: $"Коментар '{id}' не існує.",
                statusCode: StatusCodes.Status404NotFound)
            : Results.Ok(comment);
    }

    private static async Task<IResult> GetSeveritySummaryAsync(
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

        var isAnalyst = httpContext.User.IsInRole(DbSeeder.AnalystRole);
        var isReporter = httpContext.User.IsInRole(DbSeeder.ReporterRole);

        if (!isAnalyst && !isReporter)
        {
            return Results.Problem(
                statusCode: StatusCodes.Status403Forbidden,
                title: "Доступ заборонено для цієї ролі.");
        }

        var ownerFilter = isAnalyst ? null : (Guid?)userId;

        var summary = await queries.GetSeveritySummaryAsync(ownerFilter, cancellationToken);
        return Results.Ok(summary);
    }
}