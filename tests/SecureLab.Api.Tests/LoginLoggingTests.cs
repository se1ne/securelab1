using System.Net;
using System.Net.Http.Json;
using SecureLab.Api.Security;

namespace SecureLab.Api.Tests;

/// <summary>REG-LOG-01 (F-01): журнал входу не містить введеного імені при невдачі.</summary>
[Collection("Serialized")]
public sealed class LoginLoggingTests
{
    private static string Pw =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    private static List<CapturingLoggerProvider.LogEntry> LoginEvents(DenialTestFactory f) =>
        f.Capture.Entries.Where(e => e.Message.StartsWith("Authentication event login")).ToList();

    [Theory]
    [InlineData("nobody-user-123", "wrong-pass-123")]   // неіснуюче ім'я
    [InlineData("alice", "wrong-pass-123")]             // існуюче ім'я, хибний пароль
    [InlineData("мій-пароль-помилково-тут", "unique-pw-not-in-logs-987")]       // пароль, введений у поле імені
    public async Task FailedLogin_DoesNotLogTypedUserName(string userName, string password)
    {
        using var factory = new DenialTestFactory();
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Test-Partition", Guid.NewGuid().ToString("N"));

        using var response = await client.PostAsJsonAsync("/api/auth/login", new { userName, password });
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        var entry = Assert.Single(LoginEvents(factory));
        Assert.Equal("failure", entry.Fields["Result"]);
        Assert.Equal(LogSanitizer.Fingerprint(userName), entry.Fields["UserRef"]);
        Assert.DoesNotContain(userName, entry.Message);
        Assert.DoesNotContain(password, entry.Message);
        Assert.DoesNotContain(factory.Capture.Entries, e => e.Message.Contains(userName) || e.Message.Contains(password));
    }

    [Fact]
    public async Task SuccessfulLogin_LogsVerifiedUser_WithoutPassword()
    {
        using var factory = new DenialTestFactory();
        using var client = await factory.LoginAsync("alice", Pw, withCsrfToken: false);

        var entry = Assert.Single(LoginEvents(factory));
        Assert.Equal("success", entry.Fields["Result"]);
        Assert.Equal("alice", entry.Fields["UserName"]);
        Assert.DoesNotContain(factory.Capture.Entries, e => e.Message.Contains(Pw));
    }

    [Fact]
    public void Fingerprint_IsStable_CaseInsensitive_AndHidesValue()
    {
        Assert.Equal(LogSanitizer.Fingerprint("Alice"), LogSanitizer.Fingerprint(" alice "));
        Assert.DoesNotContain("alice", LogSanitizer.Fingerprint("alice"));
        Assert.Equal("(missing)", LogSanitizer.Fingerprint(null));
    }
}
