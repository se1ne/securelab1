using System.Net;
using SecureLab.Api.Security;

namespace SecureLab.Api.Tests;

[Collection("Serialized")]
public sealed class SearchRateLimitTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    [Fact]
    public async Task Search_TwoPartitions_Quota_429_AndRecovery()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        using var bob = await factory.LoginAsync("bob", StudyPassword);

        // 1. Квота Alice: перші PermitLimit запитів проходять.
        for (var i = 0; i < SearchRateLimit.PermitLimit; i++)
        {
            using var ok = await alice.GetAsync("/api/incidents/search?q=a");
            Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        }

        // 2. Наступний запит у тому самому вікні отримує 429.
        using var limited = await alice.GetAsync("/api/incidents/search?q=a");
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);

        // 3. Інший partition (Bob) не зачеплено.
        using var bobOk = await bob.GetAsync("/api/incidents/search?q=a");
        Assert.Equal(HttpStatusCode.OK, bobOk.StatusCode);

        // 4. Після вікна доступ Alice відновлюється.
        await Task.Delay(SearchRateLimit.Window + TimeSpan.FromSeconds(1));
        using var recovered = await alice.GetAsync("/api/incidents/search?q=a");
        Assert.Equal(HttpStatusCode.OK, recovered.StatusCode);
    }
}
