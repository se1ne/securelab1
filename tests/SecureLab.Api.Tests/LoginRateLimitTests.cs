using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace SecureLab.Api.Tests;

public sealed class LoginRateLimitTests(
    SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    [Fact]
    public async Task LoginRateLimit_Returns429_ThenRecovers()
    {
        var password =
            Environment.GetEnvironmentVariable(
                "SeedUsers__Password")
            ?? throw new InvalidOperationException(
                "Set local SeedUsers__Password outside Git.");

        using var freshHost =
            factory.WithWebHostBuilder(_ => { });

        using var client = freshHost.CreateClient(
            new WebApplicationFactoryClientOptions
            {
                BaseAddress =
                    new Uri("https://localhost"),
                AllowAutoRedirect = false
            });

        var body = new
        {
            userName =
                "unknown" +
                Guid.NewGuid().ToString("N")[..8],
            password
        };

        for (var i = 0; i < 10; i++)
        {
            using var response =
                await client.PostAsJsonAsync(
                    "/api/auth/login",
                    body);

            Assert.Equal(
                HttpStatusCode.Unauthorized,
                response.StatusCode);
        }

        using var limitedResponse =
            await client.PostAsJsonAsync(
                "/api/auth/login",
                body);

        Assert.Equal(
            HttpStatusCode.TooManyRequests,
            limitedResponse.StatusCode);

        await Task.Delay(
            TimeSpan.FromMilliseconds(2500));

        using var recoveredResponse =
            await client.PostAsJsonAsync(
                "/api/auth/login",
                body);

        Assert.Equal(
            HttpStatusCode.Unauthorized,
            recoveredResponse.StatusCode);
    }
}