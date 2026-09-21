using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Application.Incidents;

public sealed class IncidentQueries(SecureLabDbContext dbContext, ILogger<IncidentQueries> logger)
{
    public async Task<IReadOnlyList<IncidentListItemResponse>> GetListAsync(
        IncidentStatus? status,
        CancellationToken cancellationToken)
    {
        logger.LogInformation("Loading incidents with status filter {Status}", status);

        var query = dbContext.Incidents.AsNoTracking();
        if (status is not null)
        {
            query = query.Where(incident => incident.Status == status);
        }

        return await query
            .OrderByDescending(incident => incident.CreatedAtUtc)
            .Select(incident => new IncidentListItemResponse(
                incident.Id,
                incident.Title,
                incident.Severity.ToString(),
                incident.Status.ToString(),
                incident.OccurredAtUtc,
                incident.CreatedAtUtc))
            .ToListAsync(cancellationToken);
    }

    public Task<IncidentDetailsResponse?> GetDetailsAsync(Guid id, CancellationToken cancellationToken)
    {
        var traceId = System.Diagnostics.Activity.Current?.TraceId.ToString() ?? "N/A";
        logger.LogInformation("Loading incident {IncidentId}, TraceId: {TraceId}", id, traceId);

        return dbContext.Incidents
            .AsNoTracking()
            .Where(incident => incident.Id == id)
            .Select(incident => new IncidentDetailsResponse(
                incident.Id,
                incident.Title,
                incident.Description,
                incident.Severity.ToString(),
                incident.Status.ToString(),
                incident.OccurredAtUtc,
                incident.CreatedAtUtc,
                incident.Owner.DisplayName,
                incident.Comments
                    .Where(comment => !comment.IsInternal)
                    .OrderBy(comment => comment.CreatedAtUtc)
                    .Select(comment => new IncidentCommentResponse(
                        comment.Id,
                        comment.Author.DisplayName,
                        comment.Text,
                        comment.CreatedAtUtc))
                    .ToList()))
            .SingleOrDefaultAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<IncidentSeveritySummaryResponse>> GetSeveritySummaryAsync(CancellationToken cancellationToken = default)
    {
        var rawSummary = await dbContext.Incidents
            .AsNoTracking()
            .GroupBy(i => i.Severity)
            .Select(g => new {
                Severity = g.Key,
                Count = g.Count()
            })
            .ToListAsync(cancellationToken);

        var summaryDict = rawSummary.ToDictionary(x => x.Severity, x => x.Count);
        var orderedSeverities = new[]
        {
            IncidentSeverity.Critical,
            IncidentSeverity.High,
            IncidentSeverity.Medium,
            IncidentSeverity.Low
        };
        var result = orderedSeverities
            .Select(severity => 
            {
                var severityString = severity.ToString();
                var count = summaryDict.TryGetValue(severity, out var c) ? c : 0;
                return new IncidentSeveritySummaryResponse(severityString, count);
            })
            .ToList();
        var traceId = System.Diagnostics.Activity.Current?.TraceId.ToString() ?? "N/A";
        logger.LogInformation("Сформовано підсумок інцидентів за критичністю. Груп: {GroupCount}, TraceId: {TraceId}", result.Count, traceId);

        return result;
    }

}
