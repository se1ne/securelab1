using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace SecureLab.Api.Tests;

/// <summary>REG-CSRF-01: без token — один точний 400 і стан не змінено; з token — успіх і стан змінено.</summary>
[Collection("Serialized")]
public sealed class CsrfRegressionTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private const string ProblemType = "https://securelab.local/problems/antiforgery";

    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    private static object Body(string title, DateTimeOffset occurredAt) => new
    {
        title,
        description = "Створено для перевірки antiforgery (ЛР 6).",
        severity = "Low",
        occurredAtUtc = occurredAt
    };

    private static async Task<Guid> CreateAsync(HttpClient client, string title)
    {
        using var response = await client.PostAsJsonAsync(
            "/api/incidents", Body(title, DateTimeOffset.UtcNow.AddHours(-1)));
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        return json.GetProperty("id").GetGuid();
    }

    private static async Task<JsonElement?> GetAsync(HttpClient client, Guid id)
    {
        using var response = await client.GetAsync($"/api/incidents/{id}");
        if (response.StatusCode == HttpStatusCode.NotFound) return null;
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await response.Content.ReadFromJsonAsync<JsonElement>();
    }

    private static async Task AssertAntiforgeryProblemAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(ProblemType, json.GetProperty("type").GetString());
    }

    [Fact]
    public async Task REG_CSRF_01_Put_WithoutToken_Rejected_StateUnchanged_ThenWithToken_Succeeds()
    {
        using var withToken = await factory.LoginAsync("alice", StudyPassword);
        using var cookieOnly = await factory.LoginAsync("alice", StudyPassword, withCsrfToken: false);

        var title = $"CSRF {Guid.NewGuid():N}";
        var id = await CreateAsync(withToken, title);
        try
        {
            var before = await GetAsync(withToken, id);
            Assert.Equal(title, before!.Value.GetProperty("title").GetString());
            var occurredAt = before.Value.GetProperty("occurredAtUtc").GetDateTimeOffset();
            var newTitle = title + " changed";

            // 1. Валідна cookie, але без request token: один точний 4xx.
            using var denied = await cookieOnly.PutAsJsonAsync($"/api/incidents/{id}", Body(newTitle, occurredAt));
            await AssertAntiforgeryProblemAsync(denied);

            // 2. Стан ресурсу не змінився.
            var afterDenied = await GetAsync(withToken, id);
            Assert.Equal(title, afterDenied!.Value.GetProperty("title").GetString());

            // 3. Та сама операція з токеном: успіх.
            using var allowed = await withToken.PutAsJsonAsync($"/api/incidents/{id}", Body(newTitle, occurredAt));
            Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);

            // 4. Стан змінився саме як очікувалось.
            var afterAllowed = await GetAsync(withToken, id);
            Assert.Equal(newTitle, afterAllowed!.Value.GetProperty("title").GetString());
        }
        finally
        {
            using var cleanup = await withToken.DeleteAsync($"/api/incidents/{id}");
        }
    }

    [Theory]
    [InlineData("PUT")]
    [InlineData("DELETE")]
    [InlineData("TRIAGE")]
    [InlineData("CREATE")]
    [InlineData("LOGOUT")]
    public async Task Perimeter_WithoutToken_SameFourXx_AndStateUnchanged(string route)
    {
        using var withToken = await factory.LoginAsync("alice", StudyPassword);
        using var aliceCookieOnly = await factory.LoginAsync("alice", StudyPassword, withCsrfToken: false);
        using var morganCookieOnly = await factory.LoginAsync("morgan", StudyPassword, withCsrfToken: false);
        using var morganWithToken = await factory.LoginAsync("morgan", StudyPassword);

        var title = $"CSRF perimeter {route} {Guid.NewGuid():N}";
        Guid? id = route == "CREATE" || route == "LOGOUT" ? null : await CreateAsync(withToken, title);
        try
        {
            switch (route)
            {
                case "PUT":
                {
                    using var r = await aliceCookieOnly.PutAsJsonAsync(
                        $"/api/incidents/{id}", Body(title + " x", DateTimeOffset.UtcNow.AddHours(-1)));
                    await AssertAntiforgeryProblemAsync(r);
                    Assert.Equal(title, (await GetAsync(withToken, id!.Value))!.Value.GetProperty("title").GetString());
                    break;
                }
                case "DELETE":
                {
                    using var r = await aliceCookieOnly.DeleteAsync($"/api/incidents/{id}");
                    await AssertAntiforgeryProblemAsync(r);
                    Assert.NotNull(await GetAsync(withToken, id!.Value));
                    break;
                }
                case "TRIAGE":
                {
                    using var r = await morganCookieOnly.PostAsJsonAsync($"/api/incidents/{id}/triage", new { });
                    await AssertAntiforgeryProblemAsync(r);
                    Assert.Equal("New", (await GetAsync(morganWithToken, id!.Value))!.Value.GetProperty("status").GetString());
                    break;
                }
                case "CREATE":
                {
                    using var r = await aliceCookieOnly.PostAsJsonAsync(
                        "/api/incidents", Body(title, DateTimeOffset.UtcNow.AddHours(-1)));
                    await AssertAntiforgeryProblemAsync(r);
                    var list = await withToken.GetFromJsonAsync<JsonElement>("/api/incidents");
                    Assert.DoesNotContain(list.EnumerateArray(), item => item.GetProperty("title").GetString() == title);
                    break;
                }
                case "LOGOUT":
                {
                    using var r = await aliceCookieOnly.PostAsync("/api/auth/logout", null);
                    await AssertAntiforgeryProblemAsync(r);
                    using var me = await aliceCookieOnly.GetAsync("/api/me");
                    Assert.Equal(HttpStatusCode.OK, me.StatusCode);
                    break;
                }
            }
        }
        finally
        {
            if (id is not null)
            {
                using var cleanup = await withToken.DeleteAsync($"/api/incidents/{id}");
            }
        }
    }
}
