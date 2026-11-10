using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace SecureLab.Api.Tests;

public static class CookieClient
{
    /// <param name="withCsrfToken">
    /// true (за замовчуванням): після входу одержує antiforgery token і додає header до всіх запитів клієнта.
    /// false: клієнт має лише cookie сеансу (для негативних перевірок CSRF).
    /// </param>
    public static async Task<HttpClient> LoginAsync(
        this WebApplicationFactory<Program> factory, string userName, string password, bool withCsrfToken = true)
    {
        // Кожен тест починає з чистими лічильниками відмов (спільний хост між тестами).
        (factory.Services.GetService(typeof(SecureLab.Api.Security.AuthorizationDenialTracker))
            as SecureLab.Api.Security.AuthorizationDenialTracker)?.Reset();
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false, HandleCookies = true
        });
        client.DefaultRequestHeaders.Add("X-Test-Partition", Guid.NewGuid().ToString("N"));

        using var response = await client.PostAsJsonAsync("/api/auth/login", new { userName, password });
        if (!response.IsSuccessStatusCode)
        {
            client.Dispose();
            throw new InvalidOperationException("Study login failed (credentials omitted).");
        }

        if (withCsrfToken)
        {
            using var tokenResponse = await client.GetAsync("/api/auth/csrf-token");
            if (!tokenResponse.IsSuccessStatusCode)
            {
                client.Dispose();
                throw new InvalidOperationException("Antiforgery token request failed.");
            }

            var json = await tokenResponse.Content.ReadFromJsonAsync<JsonElement>();
            client.DefaultRequestHeaders.Add(
                json.GetProperty("headerName").GetString()!,
                json.GetProperty("token").GetString()!);
        }

        return client;
    }
}
