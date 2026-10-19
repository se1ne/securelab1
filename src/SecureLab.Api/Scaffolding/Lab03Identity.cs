using Microsoft.AspNetCore.Identity;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using System.Net.Mail;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using Microsoft.AspNetCore.RateLimiting;

namespace SecureLab.Api.Scaffolding;

public static class Lab03Identity
{
    public static void AddLab03Identity(this WebApplicationBuilder builder)
    {
        builder.Services.AddIdentity<ApplicationUser, IdentityRole<Guid>>(options =>
        {
            options.User.RequireUniqueEmail = true;
            options.Password.RequiredLength = 10;
        }).AddEntityFrameworkStores<SecureLabDbContext>().AddDefaultTokenProviders();
        builder.Services.AddAuthorization();
        builder.Services.ConfigureApplicationCookie(options =>
        {
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
                ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
            options.Events.OnRedirectToLogin = context =>
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            };
            options.Events.OnRedirectToAccessDenied = context =>
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return Task.CompletedTask;
            };
        });
    }

    public static void MapLab03Identity(this WebApplication app)
    {
        app.MapPost("/api/auth/register", async (
            RegistrationInput input,
            UserManager<ApplicationUser> users) =>
        {
            var errors = new Dictionary<string, string[]>();

            var userName = input.UserName?.Trim() ?? "";
            var email = input.Email?.Trim() ?? "";
            var displayName = input.DisplayName?.Trim() ?? "";

            if (string.IsNullOrWhiteSpace(userName))
                errors["userName"] = ["Ім'я користувача обов'язкове."];
            else if (userName.Length > 256)
                errors["userName"] = ["Ім'я користувача не може перевищувати 256 символів."];

            if (string.IsNullOrWhiteSpace(email))
            {
                errors["email"] = ["Email обов'язковий."];
            }
            else if (email.Length > 256)
            {
                errors["email"] = ["Email не може перевищувати 256 символів."];
            }
            else
            {
                try
                {
                    _ = new MailAddress(email);
                }
                catch
                {
                    errors["email"] = ["Email має некоректний формат."];
                }
            }

            if (string.IsNullOrWhiteSpace(displayName))
                errors["displayName"] = ["Відображуване ім'я обов'язкове."];
            else if (displayName.Length > 120)
                errors["displayName"] = ["Відображуване ім'я не може перевищувати 120 символів."];

            if (string.IsNullOrEmpty(input.Password))
                errors["password"] = ["Пароль обов'язковий."];

            if (errors.Count > 0)
                return Results.ValidationProblem(errors);

            var user = new ApplicationUser
            {
                Id = Guid.NewGuid(),
                UserName = userName,
                Email = email,
                DisplayName = displayName
            };

            var result = await users.CreateAsync(user, input.Password!);

            if (!result.Succeeded)
            {
                var codes = result.Errors
                    .Select(error => error.Code)
                    .ToArray();

                if (codes.Contains("DuplicateUserName")
                    || codes.Contains("DuplicateEmail"))
                {
                    return Results.Conflict(new ProblemDetails
                    {
                        Status = StatusCodes.Status409Conflict,
                        Title = "Registration conflict",
                        Detail = "Користувач з таким ім'ям або email уже існує."
                    });
                }

                return Results.ValidationProblem(
                    new Dictionary<string, string[]>
                    {
                        ["registration"] =
                        [
                            "Реєстрацію відхилено. Перевірте введені дані."
                        ]
                    });
            }

            var roleResult = await users.AddToRoleAsync(user, DbSeeder.ReporterRole);

            if (!roleResult.Succeeded)
                throw new InvalidOperationException("Default role assignment failed.");

            var response = new RegistrationResponse(
                user.Id,
                user.UserName!,
                user.DisplayName
            );

            return Results.Created("/api/me", response);
        });
        app.MapPost("/api/auth/login", async (
            LoginInput input,
            SignInManager<ApplicationUser> signIn,
            HttpContext context,
            ILogger<Program> logger) =>
        {
            if (string.IsNullOrWhiteSpace(input.UserName)
                || string.IsNullOrEmpty(input.Password))
            {
                logger.LogInformation(
                    "Authentication event {EventType}: user {UserName}, result {Result}, trace {TraceId}",
                    "login",
                    input.UserName ?? "(missing)",
                    "failure",
                    context.TraceIdentifier);

                return Results.Unauthorized();
            }

            var result = await signIn.PasswordSignInAsync(
                input.UserName,
                input.Password,
                isPersistent: false,
                lockoutOnFailure: false);

            logger.LogInformation(
                "Authentication event {EventType}: user {UserName}, result {Result}, trace {TraceId}",
                "login",
                input.UserName,
                result.Succeeded ? "success" : "failure",
                context.TraceIdentifier);

            return result.Succeeded
                ? Results.NoContent()
                : Results.Unauthorized();
        })
        .RequireRateLimiting("login");
        app.MapPost("/api/auth/logout", async (
            SignInManager<ApplicationUser> signIn) =>
        {
            await signIn.SignOutAsync();

            return Results.NoContent();
        })
        .RequireAuthorization();
        // Навмисно хибна навчальна довіра: ЛР 03 замінює заявлений id на verified principal.
        app.MapGet("/api/me", async (
            HttpContext context,
            UserManager<ApplicationUser> users) =>
        {
            var userIdValue =
                context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            if (!Guid.TryParse(userIdValue, out var userId))
            {
                return Results.Problem(
                    statusCode: StatusCodes.Status500InternalServerError,
                    title: "Authenticated user identifier is invalid.");
            }

            var user = await users.FindByIdAsync(userId.ToString());

            if (user is null)
            {
                return Results.Problem(
                    statusCode: StatusCodes.Status500InternalServerError,
                    title: "Authenticated user was not found.");
            }

            var response = new CurrentUserResponse(
                user.Id,
                user.UserName ?? string.Empty,
                user.DisplayName);

            return Results.Ok(response);
        })
        .RequireAuthorization();
        // Приклад лише mechanics: не повертає identity і не реалізує оцінювану operation.
        app.MapGet("/api/auth/session-check", () => Results.NoContent()).RequireAuthorization();
    }
}

public sealed record RegistrationInput(string? UserName, string? Email, string? DisplayName, string? Password);

public sealed record RegistrationResponse(
    Guid Id,
    string UserName,
    string DisplayName
);
public sealed record LoginInput(string? UserName, string? Password);

public sealed record CurrentUserResponse(
    Guid Id,
    string UserName,
    string DisplayName);