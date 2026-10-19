using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Tests;

public sealed class PasswordHasherUpgradeTests
{
    [Fact]
    public void StrongerHasher_RecognizesOlderHash_AsNeedingRehash()
    {
        var user = new ApplicationUser
        {
            Id = Guid.NewGuid(),
            UserName = "rehash-test",
            DisplayName = "Rehash Test"
        };

        const string password = "UpgradeTest-123!";

        var oldHasher = new PasswordHasher<ApplicationUser>(
            Options.Create(new PasswordHasherOptions
            {
                CompatibilityMode =
                    PasswordHasherCompatibilityMode.IdentityV3,
                IterationCount = 10_000
            }));

        var strongerHasher = new PasswordHasher<ApplicationUser>(
            Options.Create(new PasswordHasherOptions
            {
                CompatibilityMode =
                    PasswordHasherCompatibilityMode.IdentityV3,
                IterationCount = 100_000
            }));

        var oldHash =
            oldHasher.HashPassword(user, password);

        var result =
            strongerHasher.VerifyHashedPassword(
                user,
                oldHash,
                password);

        Assert.Equal(
            PasswordVerificationResult.SuccessRehashNeeded,
            result);
    }
}