using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
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