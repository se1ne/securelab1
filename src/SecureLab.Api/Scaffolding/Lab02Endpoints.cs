using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;
using System.Security.Claims;

namespace SecureLab.Api.Scaffolding;

// Навчальний старт ЛР 02. Запускати лише з локальними штучними даними.
public static class Lab02Endpoints
{
    private static string EscapeLike(string value) =>
    value.Replace("\\", "\\\\")
         .Replace("%", "\\%")
         .Replace("_", "\\_");

    public static void MapLab02Endpoints(this WebApplication app)
    {
                app.MapGet("/api/incidents/search", async (
            string? q,
            string? sortBy,
            HttpContext httpContext,
            SecureLabDbContext db,
            CancellationToken ct) =>
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

            var pattern = "%" + EscapeLike(q ?? "") + "%";

            var found = db.Incidents.AsNoTracking()
                .Where(item => EF.Functions.ILike(item.Title, pattern, "\\")
                            || EF.Functions.ILike(item.Description, pattern, "\\"));

            if (!isAnalyst)
            {
                found = found.Where(item => item.OwnerUserId == userId);
            }

            IQueryable<Incident>? ordered = sortBy switch
            {
                null or "" or "createdAtUtc" => found
                    .OrderByDescending(item => item.CreatedAtUtc)
                    .ThenBy(item => item.Id),
                "severity" => found
                    .OrderBy(item => item.Severity == IncidentSeverity.Critical ? 0
                                : item.Severity == IncidentSeverity.High ? 1
                                : item.Severity == IncidentSeverity.Medium ? 2 : 3)
                    .ThenBy(item => item.Id),
                "status" => found
                    .OrderBy(item => item.Status == IncidentStatus.New ? 0
                                : item.Status == IncidentStatus.Triaged ? 1
                                : item.Status == IncidentStatus.InProgress ? 2
                                : item.Status == IncidentStatus.Resolved ? 3 : 4)
                    .ThenBy(item => item.Id),
                _ => null
            };

            if (ordered is null)
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["sortBy"] = ["Допустимі значення: createdAtUtc, severity, status."]
                });

            var items = await ordered
                .Take(50)
                .Select(item => new IncidentSearchItem(
                    item.Id, item.Title, item.Description,
                    item.Severity.ToString(), item.Status.ToString(), item.CreatedAtUtc))
                .ToListAsync(ct);

            return Results.Ok(items);
        })
        .RequireAuthorization();
        
        app.MapPost("/api/incidents", async (
            CreateIncidentRequest request,
            HttpContext httpContext,
            SecureLabDbContext db,
            CancellationToken ct) =>
        {
            var userIdValue = httpContext.User
                .FindFirst(ClaimTypes.NameIdentifier)?
                .Value;

            if (!Guid.TryParse(userIdValue, out var ownerUserId))
            {
                return Results.Problem(
                    statusCode: StatusCodes.Status500InternalServerError,
                    title: "Authenticated user identifier is invalid.");
            }
            // ЛР 02: доповніть server validation, business rules та response contract.
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

            if (!errors.ContainsKey("title")
                && !errors.ContainsKey("description")
                && string.Equals(title, description, StringComparison.Ordinal))
            {
                errors["description"] =
                    ["Опис не може повністю збігатися з темою інциденту."];
}

            if (errors.Count > 0)
                return Results.ValidationProblem(errors);

            var activeStatuses = new[]
            {
                IncidentStatus.New, IncidentStatus.Triaged,
                IncidentStatus.InProgress, IncidentStatus.Resolved
            };
            var isDuplicate = await db.Incidents.AnyAsync(
                item => item.Title == title && activeStatuses.Contains(item.Status), ct);
            if (isDuplicate)
                return Results.Problem(
                    statusCode: StatusCodes.Status409Conflict,
                    title: "Інцидент із такою темою вже активний",
                    detail: "Інцидент з такою самою темою вже існує в одному з активних статусів.");            

            var occurredAtUtc = request.OccurredAtUtc!.Value.ToUniversalTime();

            var incident = new Incident
            {
                Id = Guid.NewGuid(),
                OwnerUserId = ownerUserId,
                Title = title,
                Description = description,
                Severity = severity,
                Status = IncidentStatus.New,
                OccurredAtUtc = occurredAtUtc,
                CreatedAtUtc = now,
                UpdatedAtUtc = now
            };
            db.Incidents.Add(incident);
            await db.SaveChangesAsync(ct);

            var response = new CreatedIncidentResponse(
                incident.Id, incident.Title, incident.Severity.ToString(),
                incident.Status.ToString(), incident.OccurredAtUtc, incident.CreatedAtUtc);
            return Results.Created($"/api/incidents/{incident.Id}", response);
})
.RequireAuthorization();
    }
}

public sealed record CreateIncidentRequest(
    string? Title, string? Description, string? Severity, DateTimeOffset? OccurredAtUtc);

public sealed record IncidentSearchItem(
    Guid Id, string Title, string Description,
    string Severity, string Status, DateTimeOffset CreatedAtUtc);
