using System.Net;

namespace SecureLab.Api.Tests;

/// <summary>REG-CORS-01 і REG-HDR-01: чужий origin не отримує дозволу CORS; заголовки безпеки є у відповідях API.</summary>
[Collection("Serialized")]
public sealed class CorsAndHeadersTests
{
    private const string ForeignOrigin = "https://evil.example";

    [Fact]
    public async Task REG_CORS_01_ForeignOrigin_GetsNoCorsPermission()
    {
        using var factory = new DenialTestFactory();
        using var client = factory.CreateClient();

        using var simple = new HttpRequestMessage(HttpMethod.Get, "/api/incidents");
        simple.Headers.Add("Origin", ForeignOrigin);
        using var simpleResponse = await client.SendAsync(simple);
        Assert.False(simpleResponse.Headers.Contains("Access-Control-Allow-Origin"));
        Assert.False(simpleResponse.Headers.Contains("Access-Control-Allow-Credentials"));

        using var preflight = new HttpRequestMessage(HttpMethod.Options, "/api/incidents");
        preflight.Headers.Add("Origin", ForeignOrigin);
        preflight.Headers.Add("Access-Control-Request-Method", "POST");
        using var preflightResponse = await client.SendAsync(preflight);
        Assert.False(preflightResponse.Headers.Contains("Access-Control-Allow-Origin"));
        Assert.False(preflightResponse.Headers.Contains("Access-Control-Allow-Methods"));
        Assert.False(preflightResponse.Headers.Contains("Access-Control-Allow-Credentials"));
    }

    [Fact]
    public async Task REG_HDR_01_ApiResponses_HaveSecurityHeaders()
    {
        using var factory = new DenialTestFactory();
        using var client = factory.CreateClient();

        using var response = await client.GetAsync("/api/incidents");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("no-referrer", response.Headers.GetValues("Referrer-Policy").Single());
        var csp = response.Headers.GetValues("Content-Security-Policy").Single();
        Assert.Contains("default-src 'self'", csp);
        Assert.Contains("frame-ancestors 'none'", csp);
    }
}
