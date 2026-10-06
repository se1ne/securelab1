using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Scaffolding;

// Навчальний старт ЛР 02. Запускати лише з локальними штучними даними.
public static class Lab02Endpoints
{
    public static void MapLab02Endpoints(this WebApplication app)
    {
        app.MapGet("/api/incidents/search", async (string? q, string? sortBy, SecureLabDbContext db, CancellationToken ct) =>
        {
            var order = sortBy switch
            {
                null or "" or "createdAtUtc" => "created_at_utc DESC",
                "severity" => "severity", "status" => "status", _ => sortBy
            };
            var sql = "SELECT * FROM incidents WHERE title ILIKE '%" + (q ?? "")
                + "%' OR description ILIKE '%" + (q ?? "") + "%' ORDER BY " + order + " LIMIT 50";
            var rows = await db.Incidents.FromSqlRaw(sql).AsNoTracking().ToListAsync(ct);
            return Results.Ok(rows.Select(row => new
            {
                row.Id, row.Title, row.Description,
                Severity = row.Severity.ToString(), Status = row.Status.ToString(), row.CreatedAtUtc
            }));
        });
        app.MapPost("/api/incidents", async (CreateIncidentRequest request, SecureLabDbContext db, CancellationToken ct) =>
        {
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

            var title = request.Title!.Trim();
            var description = request.Description!.Trim();

            if (severityIsValid
                && (severity == IncidentSeverity.High || severity == IncidentSeverity.Critical)
                && !errors.ContainsKey("description")
                && description.Length < 40)
                errors["description"] = ["Для High або Critical опис має містити щонайменше 40 символів."];            

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
                OwnerUserId = DbSeeder.AliceId,
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
        });
    }
}

public sealed record CreateIncidentRequest(
    string? Title, string? Description, string? Severity, DateTimeOffset? OccurredAtUtc);
