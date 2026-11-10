using System.Collections.Concurrent;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;

namespace SecureLab.Api.Tests;

/// <summary>Власний fake вбудованого TimeProvider (без нових пакетів).</summary>
public sealed class TestTimeProvider(DateTimeOffset start) : TimeProvider
{
    private long _ticks = start.UtcTicks;

    public override DateTimeOffset GetUtcNow() =>
        new(Interlocked.Read(ref _ticks), TimeSpan.Zero);

    public void Advance(TimeSpan by) => Interlocked.Add(ref _ticks, by.Ticks);
}

/// <summary>In-memory ILoggerProvider: тест читає structured-записи журналу.</summary>
public sealed class CapturingLoggerProvider : ILoggerProvider
{
    public sealed record LogEntry(
        string Category, LogLevel Level, string Message, IReadOnlyDictionary<string, object?> Fields);

    public ConcurrentQueue<LogEntry> Entries { get; } = new();

    public ILogger CreateLogger(string categoryName) => new CapturingLogger(categoryName, Entries);

    public void Dispose() { }

    private sealed class CapturingLogger(string category, ConcurrentQueue<LogEntry> sink) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            var fields = new Dictionary<string, object?>();
            if (state is IEnumerable<KeyValuePair<string, object?>> pairs)
            {
                foreach (var pair in pairs) fields[pair.Key] = pair.Value;
            }
            sink.Enqueue(new LogEntry(category, logLevel, formatter(state, exception), fields));
        }
    }
}

/// <summary>Окремий тестовий хост: fake TimeProvider + читання журналу в пам'яті.</summary>
public sealed class DenialTestFactory : WebApplicationFactory<Program>
{
    public TestTimeProvider Clock { get; } = new(DateTimeOffset.UtcNow);

    public CapturingLoggerProvider Capture { get; } = new();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");
        builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<TimeProvider>();
            services.AddSingleton<TimeProvider>(Clock);
            services.AddSingleton<ILoggerProvider>(Capture);
        });
    }
}
