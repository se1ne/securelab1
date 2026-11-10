using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

/// <summary>REG-AUDIT-01: успішний triage лишає audit-запис; невдалі спроби його не створюють.</summary>
[Collection("Serialized")]
public sealed class TriageAuditTests
{
    private static string Pw =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    private static List<CapturingLoggerProvider.LogEntry> Triaged(DenialTestFactory f) =>
        f.Capture.Entries
            .Where(e => e.Category == "Audit" && (string?)e.Fields["EventType"] == "incident.triaged")
            .ToList();

    [Fact]
    public async Task Triage_Success_WritesOneAuditRecord_RepeatedAndForbiddenDoNot()
    {
        using var factory = new DenialTestFactory();
        using var alice = await factory.LoginAsync("alice", Pw);

        using var created = await alice.PostAsJsonAsync("/api/incidents", new
        {
            title = $"Triage audit {Guid.NewGuid():N}",
            description = "Створено для перевірки audit triage.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddHours(-1)
        });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var id = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();

        try
        {
            // Reporter не має права: відмова не є успішним triage.
            using (var forbidden = await alice.PostAsync($"/api/incidents/{id}/triage", null))
                Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);
            Assert.Empty(Triaged(factory));

            using var morgan = await factory.LoginAsync("morgan", Pw);
            using (var ok = await morgan.PostAsync($"/api/incidents/{id}/triage", null))
                Assert.Equal(HttpStatusCode.NoContent, ok.StatusCode);

            var entry = Assert.Single(Triaged(factory));
            Assert.Equal((object)DbSeeder.MorganId, entry.Fields["Subject"]);
            Assert.Equal(id.ToString(), entry.Fields["Resource"]);
            Assert.Equal("success", entry.Fields["Result"]);
            Assert.StartsWith("POST ", (string)entry.Fields["Action"]!);
            Assert.False(string.IsNullOrWhiteSpace((string?)entry.Fields["TraceId"]));
            Assert.IsType<DateTimeOffset>(entry.Fields["Time"]);

            // Повторний triage (409) нового запису не створює.
            using (var again = await morgan.PostAsync($"/api/incidents/{id}/triage", null))
                Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);
            Assert.Single(Triaged(factory));
        }
        finally
        {
            using var cleanup = await alice.DeleteAsync($"/api/incidents/{id}");
        }
    }
}
