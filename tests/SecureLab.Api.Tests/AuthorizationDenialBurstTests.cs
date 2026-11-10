using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SecureLab.Api.Data;
using SecureLab.Api.Security;

namespace SecureLab.Api.Tests;

/// <summary>REG-DENY-01: audit відмов, burst на 5-й відмові, 429, ізоляція, скидання, вилучення partition.</summary>
[Collection("Serialized")]
public sealed class AuthorizationDenialBurstTests
{
    private const string AliceIncident = "20000000-0000-0000-0000-000000000001";
    private const string AliceComment = "30000000-0000-0000-0000-000000000001";
    private const string Missing = "99999999-9999-9999-9999-999999999999";
    private const string BurstType = "https://securelab.local/problems/authorization-denied-burst";

    private static string Pw =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    private static Guid UserId(string user) => user switch
    {
        "alice" => DbSeeder.AliceId,
        "bob" => DbSeeder.BobId,
        "morgan" => DbSeeder.MorganId,
        "admin" => DbSeeder.AdminId,
        _ => throw new ArgumentException(user)
    };

    private static object ValidUpdate(string title = "Оновлений заголовок") => new
    {
        title,
        description = "Опис для перевірки відмови доступу (ЛР 6).",
        severity = "Low",
        occurredAtUtc = DateTimeOffset.UtcNow.AddHours(-1)
    };

    private static List<CapturingLoggerProvider.LogEntry> Audit(DenialTestFactory f) =>
        f.Capture.Entries.Where(e => e.Category == "Audit").ToList();

    private static List<CapturingLoggerProvider.LogEntry> Denied(DenialTestFactory f) =>
        Audit(f).Where(e => (string?)e.Fields["EventType"] == "authorization.denied").ToList();

    private static List<CapturingLoggerProvider.LogEntry> Bursts(DenialTestFactory f) =>
        Audit(f).Where(e => (string?)e.Fields["EventType"] == "authorization.denied.burst").ToList();

    private static async Task Block(HttpClient client)
    {
        for (var i = 0; i < AuthorizationDenialTracker.Threshold; i++)
        {
            using var r = await client.GetAsync($"/api/incidents/{Missing}");
            Assert.Equal(HttpStatusCode.NotFound, r.StatusCode);
        }
    }

    private static async Task Assert429Async(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(BurstType, json.GetProperty("type").GetString());
        Assert.True(response.Headers.TryGetValues("Retry-After", out var values));
        var seconds = int.Parse(values!.Single());
        Assert.InRange(seconds, 1, (int)AuthorizationDenialTracker.Window.TotalSeconds);
    }

    // Матриця: кожна відмова = один audit-запис з усіма полями.
    [Theory]
    [InlineData("bob", "GET", "/api/incidents/" + AliceIncident, 404)]                  // чужий запис
    [InlineData("alice", "GET", "/api/incidents/" + Missing, 404)]                      // неіснуючий id (рахується так само)
    [InlineData("bob", "PUT", "/api/incidents/" + AliceIncident, 404)]
    [InlineData("bob", "DELETE", "/api/incidents/" + AliceIncident, 404)]
    [InlineData("alice", "POST", "/api/incidents/" + AliceIncident + "/triage", 403)]   // Reporter не triage
    [InlineData("alice", "GET", "/api/incident-comments/" + AliceComment, 403)]         // внутрішні коментарі лише Analyst
    [InlineData("admin", "GET", "/api/incidents", 403)]                                 // роль без доступу до list
    [InlineData("admin", "GET", "/api/incidents/search?q=a", 403)]
    [InlineData("admin", "GET", "/api/incidents/severity-summary", 403)]
    public async Task Denied_Action_WritesOneAuditRecord(string user, string method, string path, int expected)
    {
        using var factory = new DenialTestFactory();
        using var client = await factory.LoginAsync(user, Pw);

        using var request = new HttpRequestMessage(new HttpMethod(method), path);
        if (method == "PUT") request.Content = JsonContent.Create(ValidUpdate());
        if (method == "POST") request.Content = JsonContent.Create(new { });

        using var response = await client.SendAsync(request);
        Assert.Equal(expected, (int)response.StatusCode);

        var entry = Assert.Single(Denied(factory));
        Assert.Equal((object)UserId(user), entry.Fields["Subject"]);
        Assert.StartsWith(method + " ", (string)entry.Fields["Action"]!);
        Assert.Equal(expected == 403 ? "forbidden" : "not-found", entry.Fields["Result"]);
        Assert.False(string.IsNullOrWhiteSpace((string?)entry.Fields["Resource"]));
        Assert.False(string.IsNullOrWhiteSpace((string?)entry.Fields["TraceId"]));
        Assert.IsType<DateTimeOffset>(entry.Fields["Time"]);
        Assert.Empty(Bursts(factory));
        Assert.DoesNotContain(Pw, entry.Message);
    }

    // Фільтрація «лише власні записи» не є відмовою; дозволені дії не створюють запису.
    [Fact]
    public async Task Allowed_Actions_DoNotCreateDenialRecords()
    {
        using var factory = new DenialTestFactory();
        using var alice = await factory.LoginAsync("alice", Pw);

        using (var r = await alice.GetAsync("/api/incidents/" + AliceIncident)) Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        using (var r = await alice.GetAsync("/api/incidents")) Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        using (var r = await alice.GetAsync("/api/incidents/search?q=a")) Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        using (var r = await alice.GetAsync("/api/incidents/severity-summary")) Assert.Equal(HttpStatusCode.OK, r.StatusCode);

        Assert.Empty(Denied(factory));
        Assert.Empty(Bursts(factory));
    }

    [Fact]
    public async Task FifthDenial_LogsBurstOnce_Then429_NotCounted_OtherUserUnaffected()
    {
        using var factory = new DenialTestFactory();
        using var alice = await factory.LoginAsync("alice", Pw);
        using var bob = await factory.LoginAsync("bob", Pw);

        await Block(alice);

        Assert.Equal(5, Denied(factory).Count);
        var burst = Assert.Single(Bursts(factory));
        Assert.Equal(LogLevel.Warning, burst.Level);
        Assert.Equal((object)DbSeeder.AliceId, burst.Fields["Subject"]);

        // Далі запити Alice отримують 429, але не додають ні відмов, ні нових burst.
        for (var i = 0; i < 2; i++)
        {
            using var blocked = await alice.GetAsync($"/api/incidents/{Missing}");
            await Assert429Async(blocked);
        }
        Assert.Equal(5, Denied(factory).Count);
        Assert.Single(Bursts(factory));

        // Ізоляція: Bob не залежить від Alice.
        using var bobOk = await bob.GetAsync("/api/incidents");
        Assert.Equal(HttpStatusCode.OK, bobOk.StatusCode);
    }

    [Fact]
    public async Task Blocked_Mutations_Return429_AndDoNotChangeState()
    {
        using var factory = new DenialTestFactory();
        using var alice = await factory.LoginAsync("alice", Pw);

        var title = $"Burst {Guid.NewGuid():N}";
        using var created = await alice.PostAsJsonAsync("/api/incidents", new
        {
            title, description = "Створено для перевірки блокування.", severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddHours(-1)
        });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var id = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();

        await Block(alice);

        var otherTitle = $"Burst new {Guid.NewGuid():N}";
        using (var put = await alice.PutAsJsonAsync($"/api/incidents/{id}", ValidUpdate(title + " changed")))
            await Assert429Async(put);
        using (var del = await alice.DeleteAsync($"/api/incidents/{id}"))
            await Assert429Async(del);
        using (var post = await alice.PostAsJsonAsync("/api/incidents", new
        {
            title = otherTitle, description = "Не має бути створено.", severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddHours(-1)
        }))
            await Assert429Async(post);

        // Після вікна стан ресурсу незмінний: дозволена мутація під 429 нічого не зробила.
        factory.Clock.Advance(AuthorizationDenialTracker.Window + TimeSpan.FromSeconds(1));
        var after = await alice.GetFromJsonAsync<JsonElement>($"/api/incidents/{id}");
        Assert.Equal(title, after.GetProperty("title").GetString());
        var list = await alice.GetFromJsonAsync<JsonElement>("/api/incidents");
        Assert.DoesNotContain(list.EnumerateArray(), item => item.GetProperty("title").GetString() == otherTitle);

        using var cleanup = await alice.DeleteAsync($"/api/incidents/{id}");
    }

    [Fact]
    public async Task Logout_StaysAvailable_WhileBlocked()
    {
        using var factory = new DenialTestFactory();
        using var alice = await factory.LoginAsync("alice", Pw);
        await Block(alice);

        using var blocked = await alice.GetAsync("/api/incidents");
        await Assert429Async(blocked);

        using var logout = await alice.PostAsync("/api/auth/logout", null);
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);

        using var me = await alice.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.Unauthorized, me.StatusCode);
    }

    [Fact]
    public async Task AfterWindow_AccessRecovers_AndNewWindowCanLogBurstAgain()
    {
        using var factory = new DenialTestFactory();
        using var alice = await factory.LoginAsync("alice", Pw);

        await Block(alice);
        Assert.Single(Bursts(factory));

        factory.Clock.Advance(AuthorizationDenialTracker.Window + TimeSpan.FromSeconds(1));

        using var ok = await alice.GetAsync("/api/incidents/" + AliceIncident);
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);

        await Block(alice);
        Assert.Equal(2, Bursts(factory).Count);   // один burst за кожне вікно
        Assert.Equal(10, Denied(factory).Count);
    }

    // Наш 429 відрізняється від 429 search limiter: Problem Details type + Retry-After.
    [Fact]
    public async Task Burst429_DiffersFrom_SearchLimiter429()
    {
        using var factory = new DenialTestFactory();
        using var alice = await factory.LoginAsync("alice", Pw);
        using var bob = await factory.LoginAsync("bob", Pw);

        for (var i = 0; i < SearchRateLimit.PermitLimit; i++)
        {
            using var ok = await bob.GetAsync("/api/incidents/search?q=a");
            Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        }
        using var searchLimited = await bob.GetAsync("/api/incidents/search?q=a");
        Assert.Equal(HttpStatusCode.TooManyRequests, searchLimited.StatusCode);
        Assert.DoesNotContain(BurstType, await searchLimited.Content.ReadAsStringAsync());
        Assert.False(searchLimited.Headers.Contains("Retry-After"));

        await Block(alice);
        using var burstLimited = await alice.GetAsync("/api/incidents");
        await Assert429Async(burstLimited);
    }

    [Fact]
    public async Task ExpiredPartitions_AreEvicted()
    {
        using var factory = new DenialTestFactory();
        using var alice = await factory.LoginAsync("alice", Pw);
        using var r = await alice.GetAsync($"/api/incidents/{Missing}");

        var tracker = factory.Services.GetRequiredService<AuthorizationDenialTracker>();
        Assert.Equal(1, tracker.PartitionCount);

        factory.Clock.Advance(TimeSpan.FromSeconds(125));
        _ = tracker.GetRetryAfter(Guid.NewGuid());   // будь-яке звернення запускає вилучення
        Assert.Equal(0, tracker.PartitionCount);
    }

    [Fact]
    public async Task ParallelDenials_AreThreadSafe_SingleBurst()
    {
        using var factory = new DenialTestFactory();
        using var _ = await factory.LoginAsync("alice", Pw);   // піднімає хост
        var tracker = factory.Services.GetRequiredService<AuthorizationDenialTracker>();
        var subject = Guid.NewGuid();

        Parallel.For(0, 50, _ => tracker.RecordDenial(subject, "GET /x", "x", 404, "trace"));

        Assert.Equal(50, Denied(factory).Count);
        Assert.Single(Bursts(factory));
        Assert.NotNull(tracker.GetRetryAfter(subject));
    }
}
