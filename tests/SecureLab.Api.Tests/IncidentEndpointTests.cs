using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using SecureLab.Api.Data;
using SecureLab.Api.Presentation.Contracts;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Tests;

[Collection("Serialized")]
public sealed class IncidentEndpointTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private readonly HttpClient _client = factory.CreateClient();

    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    [Fact]
    public async Task GetList_AsAnalyst_ReturnsAllSeededIncidents()
    {
        using var morgan = await factory.LoginAsync("morgan", StudyPassword);

        var incidents = await morgan.GetFromJsonAsync<List<IncidentListItemResponse>>("/api/incidents");

        Assert.NotNull(incidents);
        Assert.Contains(incidents, incident => incident.Id == DbSeeder.AliceIncidentId);
        Assert.Contains(incidents, incident => incident.Id == DbSeeder.BobIncidentId);
    }

[Fact]
public async Task A06_ReporterTriage_Returns403()
{
    using var alice = await factory.LoginAsync("alice", StudyPassword);

    using var response = await alice.PostAsJsonAsync(
        $"/api/incidents/{DbSeeder.AliceIncidentId}/triage", new { });

    Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
}

[Fact]
public async Task A07_AnalystTriage_NewIncident_ReturnsNoContent()
{
    using var morgan = await factory.LoginAsync("morgan", StudyPassword);
    using var alice = await factory.LoginAsync("alice", StudyPassword);

    var createPayload = new
    {
        title = "Тимчасовий інцидент для triage",
        description = "Створено спеціально для перевірки переходу New у Triaged.",
        severity = "Low",
        occurredAtUtc = DateTimeOffset.UtcNow.AddHours(-1)
    };
    using var createResponse = await alice.PostAsJsonAsync("/api/incidents", createPayload);
    var createdJson = await createResponse.Content.ReadAsStringAsync();
    using var createdDocument = JsonDocument.Parse(createdJson);
    var createdId = createdDocument.RootElement.GetProperty("id").GetGuid();

    using var triageResponse = await morgan.PostAsJsonAsync(
        $"/api/incidents/{createdId}/triage", new { });

    Assert.Equal(HttpStatusCode.NoContent, triageResponse.StatusCode);

    using var cleanup = await alice.DeleteAsync($"/api/incidents/{createdId}");
}

[Fact]
public async Task Triage_AlreadyTriaged_Returns409()
{
    using var morgan = await factory.LoginAsync("morgan", StudyPassword);

    using var response = await morgan.PostAsJsonAsync(
        $"/api/incidents/{DbSeeder.AliceIncidentId}/triage", new { });

    Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
}

[Fact]
public async Task A01_AnonymousTriage_Returns401()
{
    using var response = await _client.PostAsJsonAsync(
        $"/api/incidents/{DbSeeder.AliceIncidentId}/triage", new { });

    Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
}

    [Fact]
    public async Task A02_OwnerDelete_ReturnsNoContent()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);

        var createPayload = new
        {
            title = "Тимчасовий інцидент для видалення",
            description = "Створено спеціально для перевірки delete і буде видалено цим самим тестом.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddHours(-1)
        };

        using var createResponse = await alice.PostAsJsonAsync("/api/incidents", createPayload);
        Assert.Equal(HttpStatusCode.Created, createResponse.StatusCode);

        var createdJson = await createResponse.Content.ReadAsStringAsync();
        using var createdDocument = JsonDocument.Parse(createdJson);
        var createdId = createdDocument.RootElement.GetProperty("id").GetGuid();

        using var deleteResponse = await alice.DeleteAsync($"/api/incidents/{createdId}");
        Assert.Equal(HttpStatusCode.NoContent, deleteResponse.StatusCode);

        using var verifyResponse = await alice.GetAsync($"/api/incidents/{createdId}");
        Assert.Equal(HttpStatusCode.NotFound, verifyResponse.StatusCode);
    }

    [Fact]
    public async Task A03_NonOwnerDelete_Returns404()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);

        using var response = await alice.DeleteAsync($"/api/incidents/{DbSeeder.BobIncidentId}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task A01_AnonymousDelete_Returns401()
    {
        using var response = await _client.DeleteAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task A05_ReporterList_ReturnsOnlyOwnIncidents()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);

        var incidents = await alice.GetFromJsonAsync<List<IncidentListItemResponse>>("/api/incidents");

        Assert.NotNull(incidents);
        Assert.Contains(incidents, incident => incident.Id == DbSeeder.AliceIncidentId);
        Assert.DoesNotContain(incidents, incident => incident.Id == DbSeeder.BobIncidentId);
    }

    [Fact]
    public async Task GetList_Anonymous_Returns401()
    {
        using var response = await _client.GetAsync("/api/incidents");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task A01_AnonymousDetails_Returns401()
    {
        using var response = await _client.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task A02_OwnerDetails_ReturnsOk()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);

        using var response = await alice.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task A03_NonOwnerDetails_Returns404()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);

        using var response = await alice.GetAsync($"/api/incidents/{DbSeeder.BobIncidentId}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task A03R_AnalystDetails_ReturnsOk()
    {
        using var morgan = await factory.LoginAsync("morgan", StudyPassword);

        using var response = await morgan.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task GetDetails_ForUnknownId_ReturnsProblemDetails404()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);

        using var response = await alice.GetAsync($"/api/incidents/{Guid.NewGuid()}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task GetDetails_DoesNotExposeInternalOwnerFields()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);

        using var response = await alice.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");
        var json = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(json);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False(document.RootElement.TryGetProperty("ownerUserId", out _));
        Assert.False(document.RootElement.TryGetProperty("email", out _));
        Assert.Equal("Аліса Коваль", document.RootElement.GetProperty("ownerDisplayName").GetString());
    }

    [Fact]
    public async Task A07_AnalystReadsInternalComment_ReturnsOk()
    {
        using var morgan = await factory.LoginAsync("morgan", StudyPassword);

        using var response = await morgan.GetAsync(
            "/api/incident-comments/30000000-0000-0000-0000-000000000003");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var json = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(json);
        Assert.True(document.RootElement.GetProperty("isInternal").GetBoolean());
    }

    [Fact]
    public async Task A06_ReporterReadsInternalComment_Returns403()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);

        using var response = await alice.GetAsync(
            "/api/incident-comments/30000000-0000-0000-0000-000000000003");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task A01_AnonymousReadsInternalComment_Returns401()
    {
        using var response = await _client.GetAsync(
            "/api/incident-comments/30000000-0000-0000-0000-000000000003");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task A01_AnonymousUpdate_Returns401()
    {
        var payload = new
        {
            title = "Анонімна спроба",
            description = "Опис для перевірки відмови без автентифікації.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddHours(-1)
        };

        using var response = await _client.PutAsJsonAsync(
            $"/api/incidents/{DbSeeder.AliceIncidentId}", payload);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task A02_OwnerUpdate_ReturnsOk()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        var originalTitle = "Підозрілий лист із вкладенням";

        try
        {
            var payload = new
            {
                title = "Оновлена тема (тест)",
                description = "Оновлений опис інциденту для перевірки update.",
                severity = "Low",
                occurredAtUtc = DateTimeOffset.UtcNow.AddHours(-1)
            };

            using var response = await alice.PutAsJsonAsync(
                $"/api/incidents/{DbSeeder.AliceIncidentId}", payload);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            var json = await response.Content.ReadAsStringAsync();
            using var document = JsonDocument.Parse(json);
            Assert.Equal("Оновлена тема (тест)", document.RootElement.GetProperty("title").GetString());
        }
        finally
        {
            var restorePayload = new
            {
                title = originalTitle,
                description = "Одержано лист нібито від деканату. Вкладення не відкривалося.",
                severity = "Medium",
                occurredAtUtc = DateTimeOffset.Parse("2026-08-01T08:30:00Z")
            };
            await alice.PutAsJsonAsync($"/api/incidents/{DbSeeder.AliceIncidentId}", restorePayload);
        }
    }

    [Fact]
    public async Task A03_NonOwnerUpdate_Returns404()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);

        var payload = new
        {
            title = "Спроба чужого редагування",
            description = "Опис для перевірки відмови при редагуванні чужого інциденту.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddHours(-1)
        };

        using var response = await alice.PutAsJsonAsync(
            $"/api/incidents/{DbSeeder.BobIncidentId}", payload);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task Update_InvalidSeverity_Returns400()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);

        var payload = new
        {
            title = "Коректна тема",
            description = "Коректний опис для перевірки відмови за severity.",
            severity = "7",
            occurredAtUtc = DateTimeOffset.UtcNow.AddHours(-1)
        };

        using var response = await alice.PutAsJsonAsync(
            $"/api/incidents/{DbSeeder.AliceIncidentId}", payload);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task ClientScript_DoesNotUseDangerousInnerHtmlSink()
    {
        var script = await _client.GetStringAsync("/app.js");

        Assert.DoesNotContain("innerHTML", script, StringComparison.Ordinal);
        Assert.Contains("textContent", script, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetSeveritySummary_ReturnsExpectedDataAndCoversAllEnumValues()
    {
        var response = await _client.GetAsync("/api/incidents/severity-summary");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var summary = await response.Content.ReadFromJsonAsync<IReadOnlyList<IncidentSeveritySummaryResponse>>();
        Assert.NotNull(summary);

        var expectedOrder = new[] { "Critical", "High", "Medium", "Low" };
        var actualOrder = summary.Select(x => x.Severity).ToArray();
        Assert.Equal(expectedOrder, actualOrder);

        var summaryDict = summary.ToDictionary(x => x.Severity, x => x.Count);
        Assert.Equal(0, summaryDict["Critical"]);
        Assert.Equal(1, summaryDict["High"]);
        Assert.Equal(1, summaryDict["Medium"]);
        Assert.Equal(3, summaryDict["Low"]);

        var expectedEnumNames = Enum.GetNames<IncidentSeverity>();
        Assert.Equal(expectedEnumNames.Length, summary.Count);
        Assert.True(expectedEnumNames.ToHashSet().SetEquals(summary.Select(x => x.Severity)));
    }
}