using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Application.Incidents;

    public enum TriageResult
    {
        Success,
        NotFound,
        InvalidTransition
    }
public sealed class IncidentQueries(SecureLabDbContext dbContext, ILogger<IncidentQueries> logger)
{
    public async Task<IReadOnlyList<IncidentListItemResponse>> GetListAsync(
        IncidentStatus? status,
        Guid? ownerUserId,
        CancellationToken cancellationToken)
    {
        logger.LogInformation(
            "Loading incidents with status filter {Status} for owner {OwnerUserId}", status, ownerUserId);

        var query = dbContext.Incidents.AsNoTracking();
        if (status is not null)
        {
            query = query.Where(incident => incident.Status == status);
        }
        if (ownerUserId is not null)
        {
            query = query.Where(incident => incident.OwnerUserId == ownerUserId);
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

    public Task<IncidentDetailsResponse?> GetDetailsAsync(
        Guid id,
        Guid requestingUserId,
        bool isPrivilegedReader,
        CancellationToken cancellationToken)
    {
        var traceId = System.Diagnostics.Activity.Current?.TraceId.ToString() ?? "N/A";
        logger.LogInformation(
            "Loading incident {IncidentId} for user {UserId}, TraceId: {TraceId}",
            id, requestingUserId, traceId);

        return dbContext.Incidents
            .AsNoTracking()
            .Where(incident => incident.Id == id
                && (isPrivilegedReader || incident.OwnerUserId == requestingUserId))
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

    public async Task<IncidentDetailsResponse?> UpdateContentAsync(
        Guid id,
        Guid requestingUserId,
        string title,
        string description,
        IncidentSeverity severity,
        DateTimeOffset occurredAtUtc,
        CancellationToken cancellationToken)
    {
        var incident = await dbContext.Incidents
            .Where(item => item.Id == id && item.OwnerUserId == requestingUserId)
            .SingleOrDefaultAsync(cancellationToken);

        if (incident is null)
        {
            return null;
        }

        incident.Title = title;
        incident.Description = description;
        incident.Severity = severity;
        incident.OccurredAtUtc = occurredAtUtc;
        incident.UpdatedAtUtc = DateTimeOffset.UtcNow;

        await dbContext.SaveChangesAsync(cancellationToken);

        return await GetDetailsAsync(id, requestingUserId, isPrivilegedReader: false, cancellationToken);
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
        logger.LogInformation("Created severity summary list. Groups: {GroupCount}, TraceId: {TraceId}", result.Count, traceId);

        return result;
    }

    public async Task<bool> DeleteAsync(
        Guid id,
        Guid requestingUserId,
        CancellationToken cancellationToken)
    {
        var incident = await dbContext.Incidents
            .Where(item => item.Id == id && item.OwnerUserId == requestingUserId)
            .SingleOrDefaultAsync(cancellationToken);

        if (incident is null)
        {
            return false;
        }

        dbContext.Incidents.Remove(incident);
        await dbContext.SaveChangesAsync(cancellationToken);

        return true;
    }

    public async Task<TriageResult> TriageAsync(
        Guid id,
        CancellationToken cancellationToken)
    {
        var incident = await dbContext.Incidents
            .Where(item => item.Id == id)
            .SingleOrDefaultAsync(cancellationToken);

        if (incident is null)
        {
            return TriageResult.NotFound;
        }

        if (incident.Status != IncidentStatus.New)
        {
            return TriageResult.InvalidTransition;
        }

        incident.Status = IncidentStatus.Triaged;
        incident.UpdatedAtUtc = DateTimeOffset.UtcNow;

        await dbContext.SaveChangesAsync(cancellationToken);

        return TriageResult.Success;
    }

}
