using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

public sealed class Lab02RegressionTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    [Fact]
    public async Task T02_InvalidDto_Returns400WithTitleError()
    {
        using var client = factory.CreateClient();

        var body = new
        {
            title = " ",
            description = "Коректний опис для перевірки невалідного DTO.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-1)
        };

        using var response = await client.PostAsJsonAsync("/api/incidents", body);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        using var json = JsonDocument.Parse(
            await response.Content.ReadAsStringAsync());

        var errors = json.RootElement.GetProperty("errors");

        Assert.True(errors.TryGetProperty("title", out _));
    }

    [Fact]
    public async Task UnicodeInvisibleSymbolsError()
    {
        using var client = factory.CreateClient();

        var body = new
        {
            title = "​\u200b",
            description = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-1)
        };

        var createdTitle = "​\u200b";

        try
        {
            using var response = await client.PostAsJsonAsync("/api/incidents", body);

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

            using var json = JsonDocument.Parse(
                await response.Content.ReadAsStringAsync());

            var errors = json.RootElement.GetProperty("errors");

            Assert.True(errors.TryGetProperty("title", out _));
        }
        finally
        {
            await DeleteIncidentsByTitleAsync(createdTitle);
        }

    }


    [Fact]
    public async Task T03_DuplicateActiveTitle_Returns409()
    {
        using var client = factory.CreateClient();

        var title = $"T03-{Guid.NewGuid():N}";

        var body = new
        {
            title,
            description = "Коректний опис для перевірки предметного конфлікту.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-1)
        };

        try
        {
            using var first = await client.PostAsJsonAsync("/api/incidents", body);
            Assert.Equal(HttpStatusCode.Created, first.StatusCode);

            using var second = await client.PostAsJsonAsync("/api/incidents", body);
            Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
        }
        finally
        {
            await DeleteIncidentsByTitleAsync(title);
        }
    }

    [Fact]
    public async Task T09_HighDescriptionBoundary_Rejects39AndAccepts40()
    {
        using var client = factory.CreateClient();

        var title39 = $"T09-39-{Guid.NewGuid():N}";
        var title40 = $"T09-40-{Guid.NewGuid():N}";

        var body39 = new
        {
            title = title39,
            description = "012345678901234567890123456789012345678",
            severity = "High",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-1)
        };

        var body40 = new
        {
            title = title40,
            description = "0123456789012345678901234567890123456789",
            severity = "High",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-1)
        };

        try
        {
            using var response39 =
                await client.PostAsJsonAsync("/api/incidents", body39);

            Assert.Equal(HttpStatusCode.BadRequest, response39.StatusCode);

            using var json39 = JsonDocument.Parse(
                await response39.Content.ReadAsStringAsync());

            var errors = json39.RootElement.GetProperty("errors");

            Assert.True(errors.TryGetProperty("description", out _));

            using var response40 =
                await client.PostAsJsonAsync("/api/incidents", body40);

            Assert.Equal(HttpStatusCode.Created, response40.StatusCode);
        }
        finally
        {
            await DeleteIncidentsByTitleAsync(title39);
            await DeleteIncidentsByTitleAsync(title40);
        }
    }

    [Fact]
    public async Task S02_ControlInput_DoesNotExpandResultSet()
    {
        using var client = factory.CreateClient();

        var controlInput = "zz-no-match' OR TRUE -- ";
        var encodedInput = Uri.EscapeDataString(controlInput);

        using var response =
            await client.GetAsync($"/api/incidents/search?q={encodedInput}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var json = JsonDocument.Parse(
            await response.Content.ReadAsStringAsync());

        Assert.Equal(JsonValueKind.Array, json.RootElement.ValueKind);
        Assert.Equal(0, json.RootElement.GetArrayLength());

        using var usbResponse =
            await client.GetAsync("/api/incidents/search?q=USB");

        Assert.Equal(HttpStatusCode.OK, usbResponse.StatusCode);

        using var usbJson = JsonDocument.Parse(
            await usbResponse.Content.ReadAsStringAsync());

        Assert.Equal(1, usbJson.RootElement.GetArrayLength());

        var item = usbJson.RootElement[0];

        Assert.Equal(
            "20000000-0000-0000-0000-000000000005",
            item.GetProperty("id").GetString());
    }

    [Fact]
    public async Task T10_DescriptionEqualToTitle_Returns400()
    {
        using var client = factory.CreateClient();

        var rejectedTitle = $"T10-Reject-{Guid.NewGuid():N}";
        var acceptedTitle = $"T10-Accept-{Guid.NewGuid():N}";

        var rejectedBody = new
        {
            title = rejectedTitle,
            description = rejectedTitle,
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-1)
        };

        var acceptedBody = new
        {
            title = acceptedTitle,
            description = "Опис відрізняється від теми інциденту.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-1)
        };

        try
        {
            using var rejectedResponse =
                await client.PostAsJsonAsync("/api/incidents", rejectedBody);

            Assert.Equal(HttpStatusCode.BadRequest, rejectedResponse.StatusCode);

            using var rejectedJson = JsonDocument.Parse(
                await rejectedResponse.Content.ReadAsStringAsync());

            var errors = rejectedJson.RootElement.GetProperty("errors");

            Assert.True(errors.TryGetProperty("description", out _));

            using var acceptedResponse =
                await client.PostAsJsonAsync("/api/incidents", acceptedBody);

            Assert.Equal(HttpStatusCode.Created, acceptedResponse.StatusCode);
        }
        finally
        {
            await DeleteIncidentsByTitleAsync(rejectedTitle);
            await DeleteIncidentsByTitleAsync(acceptedTitle);
        }
    }

    [Fact]
    public async Task A02_Overposting_ServerManagedFieldsCannotBeOverridden()
    {
        using var client = factory.CreateClient();

        var title = $"A02-{Guid.NewGuid():N}";
        var suppliedId = Guid.Parse("22222222-2222-2222-2222-222222222222");
        var suppliedOwnerId = Guid.Parse("33333333-3333-3333-3333-333333333333");

        var body = new
        {
            id = suppliedId,
            ownerUserId = suppliedOwnerId,
            status = "Closed",
            createdAtUtc = "2000-01-01T00:00:00Z",

            title,
            description = "Коректний опис для перевірки захисту від overposting.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-1)
        };

        try
        {
            using var response =
                await client.PostAsJsonAsync("/api/incidents", body);

            Assert.Equal(HttpStatusCode.Created, response.StatusCode);

            using var createdJson = JsonDocument.Parse(
                await response.Content.ReadAsStringAsync());

            var createdId = createdJson.RootElement
                .GetProperty("id")
                .GetGuid();

            var status = createdJson.RootElement
                .GetProperty("status")
                .GetString();

            Assert.NotEqual(suppliedId, createdId);
            Assert.Equal("New", status);

            using var detailsResponse =
                await client.GetAsync($"/api/incidents/{createdId}");

            Assert.Equal(HttpStatusCode.OK, detailsResponse.StatusCode);

            using var detailsJson = JsonDocument.Parse(
                await detailsResponse.Content.ReadAsStringAsync());

            Assert.Equal(
                "Аліса Коваль",
                detailsJson.RootElement.GetProperty("ownerDisplayName").GetString());
        }
        finally
        {
            await DeleteIncidentsByTitleAsync(title);
        }
    }

    private async Task DeleteIncidentsByTitleAsync(string title)
    {
        using var scope = factory.Services.CreateScope();

        var db = scope.ServiceProvider
            .GetRequiredService<SecureLabDbContext>();

        await db.Incidents
            .Where(item => item.Title == title)
            .ExecuteDeleteAsync();
    }
}