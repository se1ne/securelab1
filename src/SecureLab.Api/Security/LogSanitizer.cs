using System.Security.Cryptography;
using System.Text;

namespace SecureLab.Api.Security;

public static class LogSanitizer
{
    /// <summary>
    /// Посилання на ім'я, введене користувачем, без самого значення: перші 8 hex-символів SHA-256.
    /// Дозволяє зіставити кілька спроб одного імені, але не зберігає введений текст у журналі
    /// (в поле імені можуть помилково ввести пароль або вставити керуючі символи).
    /// </summary>
    public static string Fingerprint(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "(missing)";
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(value.Trim().ToLowerInvariant()));
        return "sha256:" + Convert.ToHexString(hash, 0, 4).ToLowerInvariant();
    }
}
