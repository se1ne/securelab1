using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;

namespace SecureLab.Api.Tests;

/// <summary>REG-HTTPS-01 (F-02): при увімкненому режимі HTTPS є редирект з HTTP і заголовок HSTS на HTTPS.</summary>
[Collection("Serialized")]
public sealed class HttpsEnforcementTests
{
    private static WebApplicationFactory<Program> EnforcedFactory() =>
        new WebApplicationFactory<Program>().WithWebHostBuilder(b => b.UseSetting("Security:EnforceHttps", "true"));

    private static HttpClient Client(WebApplicationFactory<Program> f, string baseAddress) =>
        f.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri(baseAddress), AllowAutoRedirect = false });

    [Fact]
    public async Task Http_IsRedirectedToHttps_WhenEnforced()
    {
        using var factory = EnforcedFactory();
        using var client = Client(factory, "http://securelab.example");

        using var response = await client.GetAsync("/api/incidents");

        Assert.Equal(HttpStatusCode.TemporaryRedirect, response.StatusCode);
        Assert.StartsWith("https://securelab.example/api/incidents", response.Headers.Location!.ToString());
    }

    [Fact]
    public async Task Https_ResponsesCarryHsts_WhenEnforced()
    {
        using var factory = EnforcedFactory();
        using var client = Client(factory, "https://securelab.example");

        using var response = await client.GetAsync("/api/incidents");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var hsts = response.Headers.GetValues("Strict-Transport-Security").Single();
        Assert.Contains("max-age=31536000", hsts);
    }

    [Fact]
    public async Task Development_DefaultsToNoRedirect_AndNoHsts()
    {
        using var factory = new DenialTestFactory();
        using var client = Client(factory, "http://localhost");

        using var response = await client.GetAsync("/api/incidents");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.False(response.Headers.Contains("Strict-Transport-Security"));
    }
}
