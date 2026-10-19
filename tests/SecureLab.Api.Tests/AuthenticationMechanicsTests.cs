using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Tests;

public sealed class AuthenticationMechanicsTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException(
            "Set local SeedUsers__Password outside Git.");

    [Fact]
    public async Task A01_AnonymousMe_Returns401()
    {
        using var client = factory.CreateClient();

        using var response = await client.GetAsync("/api/me");

        Assert.Equal(
            HttpStatusCode.Unauthorized,
            response.StatusCode);
    }

    [Fact]
    public async Task A04_CreateWithoutOwner_UsesAuthenticatedPrincipal()
    {
        using var client =
            await factory.LoginAsync("bob", StudyPassword);

        var title =
            "A04-" + Guid.NewGuid().ToString("N")[..8];

        var body = new
        {
            title,
            description =
                "Incident created by Bob for authentication ownership test.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow
        };

        Guid createdId = Guid.Empty;

        try
        {
            using var response =
                await client.PostAsJsonAsync(
                    "/api/incidents",
                    body);

            Assert.Equal(
                HttpStatusCode.Created,
                response.StatusCode);

            using var json = JsonDocument.Parse(
                await response.Content.ReadAsStringAsync());

            createdId =
                json.RootElement
                    .GetProperty("id")
                    .GetGuid();

            using var scope =
                factory.Services.CreateScope();

            var db = scope.ServiceProvider
                .GetRequiredService<SecureLabDbContext>();

            var incident =
                await db.Incidents.FindAsync(createdId);

            Assert.NotNull(incident);

            Assert.Equal(
                DbSeeder.BobId,
                incident.OwnerUserId);
        }
        finally
        {
            if (createdId != Guid.Empty)
            {
                using var scope =
                    factory.Services.CreateScope();

                var db = scope.ServiceProvider
                    .GetRequiredService<SecureLabDbContext>();

                var incident =
                    await db.Incidents.FindAsync(createdId);

                if (incident is not null)
                {
                    db.Incidents.Remove(incident);
                    await db.SaveChangesAsync();
                }
            }
        }
    }

    [Fact]
    public async Task A05_ForgedOwnerUserId_IsIgnoredAndPrincipalWins()
    {
        using var client =
            await factory.LoginAsync("bob", StudyPassword);

        var title =
            "A05-" + Guid.NewGuid().ToString("N")[..8];

        var body = new
        {
            title,
            description =
                "Incident created by Bob with forged Alice owner identifier.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow,

            ownerUserId = DbSeeder.AliceId
        };

        Guid createdId = Guid.Empty;

        try
        {
            using var response =
                await client.PostAsJsonAsync(
                    "/api/incidents",
                    body);

            Assert.Equal(
                HttpStatusCode.Created,
                response.StatusCode);

            using var json = JsonDocument.Parse(
                await response.Content.ReadAsStringAsync());

            createdId =
                json.RootElement
                    .GetProperty("id")
                    .GetGuid();

            using var scope =
                factory.Services.CreateScope();

            var db = scope.ServiceProvider
                .GetRequiredService<SecureLabDbContext>();

            var incident =
                await db.Incidents.FindAsync(createdId);

            Assert.NotNull(incident);

            Assert.Equal(
                DbSeeder.BobId,
                incident.OwnerUserId);

            Assert.NotEqual(
                DbSeeder.AliceId,
                incident.OwnerUserId);
        }
        finally
        {
            if (createdId != Guid.Empty)
            {
                using var scope =
                    factory.Services.CreateScope();

                var db = scope.ServiceProvider
                    .GetRequiredService<SecureLabDbContext>();

                var incident =
                    await db.Incidents.FindAsync(createdId);

                if (incident is not null)
                {
                    db.Incidents.Remove(incident);
                    await db.SaveChangesAsync();
                }
            }
        }
    }

    [Fact]
    public async Task A02_LoginThenMe_ReturnsCurrentUser()
    {
        using var client =
            await factory.LoginAsync("alice", StudyPassword);

        using var response =
            await client.GetAsync("/api/me");

        Assert.Equal(
            HttpStatusCode.OK,
            response.StatusCode);

        using var json = JsonDocument.Parse(
            await response.Content.ReadAsStringAsync());

        Assert.Equal(
            "alice",
            json.RootElement
                .GetProperty("userName")
                .GetString());

        Assert.False(
            json.RootElement.TryGetProperty(
                "password",
                out _));

        Assert.False(
            json.RootElement.TryGetProperty(
                "passwordHash",
                out _));
    }

    [Fact]
    public async Task A03_ForgedDemoUserId_DoesNotChangeAuthenticatedUser()
    {
        using var client =
            await factory.LoginAsync("alice", StudyPassword);

        using var request =
            new HttpRequestMessage(
                HttpMethod.Get,
                "/api/me");

        request.Headers.Add(
            "X-Demo-UserId",
            "10000000-0000-0000-0000-000000000002");

        using var response =
            await client.SendAsync(request);

        Assert.Equal(
            HttpStatusCode.OK,
            response.StatusCode);

        using var json = JsonDocument.Parse(
            await response.Content.ReadAsStringAsync());

        Assert.Equal(
            "alice",
            json.RootElement
                .GetProperty("userName")
                .GetString());
    }

    [Fact]
    public async Task A06_LogoutThenMe_Returns401()
    {
        using var client =
            await factory.LoginAsync("alice", StudyPassword);

        using var logoutResponse =
            await client.PostAsync(
                "/api/auth/logout",
                content: null);

        Assert.Equal(
            HttpStatusCode.NoContent,
            logoutResponse.StatusCode);

        using var meResponse =
            await client.GetAsync("/api/me");

        Assert.Equal(
            HttpStatusCode.Unauthorized,
            meResponse.StatusCode);
    }

    [Fact]
public async Task A07_UnknownUserAndWrongPassword_HaveSameExternalResult()
{
    using var client = factory.CreateClient();

    var unknownUserBody = new
    {
        userName =
            "unknown" + Guid.NewGuid().ToString("N")[..8],
        password = StudyPassword
    };

    var wrongPasswordBody = new
    {
        userName = "alice",
        password = StudyPassword + "-wrong"
    };

    using var unknownUserResponse =
        await client.PostAsJsonAsync(
            "/api/auth/login",
            unknownUserBody);

    using var wrongPasswordResponse =
        await client.PostAsJsonAsync(
            "/api/auth/login",
            wrongPasswordBody);

    Assert.Equal(
        HttpStatusCode.Unauthorized,
        unknownUserResponse.StatusCode);

    Assert.Equal(
        unknownUserResponse.StatusCode,
        wrongPasswordResponse.StatusCode);

    Assert.Equal(
        unknownUserResponse.Content.Headers.ContentType?.ToString(),
        wrongPasswordResponse.Content.Headers.ContentType?.ToString());

    var unknownUserContent =
        await unknownUserResponse.Content.ReadAsStringAsync();

    var wrongPasswordContent =
        await wrongPasswordResponse.Content.ReadAsStringAsync();

    using var unknownJson =
        JsonDocument.Parse(unknownUserContent);

    using var wrongPasswordJson =
        JsonDocument.Parse(wrongPasswordContent);

    Assert.Equal(
        unknownJson.RootElement
            .GetProperty("status")
            .GetInt32(),
        wrongPasswordJson.RootElement
            .GetProperty("status")
            .GetInt32());

    Assert.Equal(
        unknownJson.RootElement
            .GetProperty("title")
            .GetString(),
        wrongPasswordJson.RootElement
            .GetProperty("title")
            .GetString());

    Assert.Equal(
        unknownJson.RootElement
            .GetProperty("type")
            .GetString(),
        wrongPasswordJson.RootElement
            .GetProperty("type")
            .GetString());
}

    [Fact]
    public async Task RealCookie_ReachesSessionCheck()
    {
        using var client = await factory.LoginAsync("alice", StudyPassword);

        using var response =
            await client.GetAsync("/api/auth/session-check");

        Assert.Equal(
            HttpStatusCode.NoContent,
            response.StatusCode);
    }

    [Fact]
    public async Task Register_DuplicateUser_Returns409()
    {
        var suffix = Guid.NewGuid().ToString("N")[..8];
        var userName = $"reg{suffix}";
        var email = $"reg{suffix}@example.test";

        var body = new
        {
            userName,
            email,
            displayName = "Student 01",
            password = StudyPassword
        };

        try
        {
            using var client = factory.CreateClient();

            using var firstResponse =
                await client.PostAsJsonAsync(
                    "/api/auth/register",
                    body);

            Assert.Equal(
                HttpStatusCode.Created,
                firstResponse.StatusCode);

            using var firstJson = JsonDocument.Parse(
                await firstResponse.Content.ReadAsStringAsync());

            Assert.Equal(
                userName,
                firstJson.RootElement
                    .GetProperty("userName")
                    .GetString());

            Assert.False(
                firstJson.RootElement.TryGetProperty(
                    "password",
                    out _));

            Assert.False(
                firstJson.RootElement.TryGetProperty(
                    "passwordHash",
                    out _));

            using var duplicateResponse =
                await client.PostAsJsonAsync(
                    "/api/auth/register",
                    body);

            Assert.Equal(
                HttpStatusCode.Conflict,
                duplicateResponse.StatusCode);
        }
        finally
        {
            using var scope = factory.Services.CreateScope();

            var users = scope.ServiceProvider
                .GetRequiredService<UserManager<ApplicationUser>>();

            var createdUser =
                await users.FindByNameAsync(userName);

            if (createdUser is not null)
                await users.DeleteAsync(createdUser);
        }
    }
}