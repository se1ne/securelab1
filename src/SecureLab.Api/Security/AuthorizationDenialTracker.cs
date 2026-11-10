using System.Collections.Concurrent;

namespace SecureLab.Api.Security;

/// <summary>
/// ЛР 6, advanced variant (а): виявлення перебору відмов.
/// Фіксоване вікно 60 с від першої відмови; partition = id користувача.
/// Лічильник у пам'яті одного екземпляра API (residual risk).
/// Audit-записи йдуть у ILogger з категорією "Audit", окремо від diagnostic log.
/// </summary>
public sealed class AuthorizationDenialTracker
{
    public const int Threshold = 5;
    public static readonly TimeSpan Window = TimeSpan.FromSeconds(60);

    private sealed class Entry
    {
        public readonly object Gate = new();
        public DateTimeOffset WindowStart;
        public int Count;
        public bool Blocked;
        public bool BurstLogged;
        public bool Removed;
        public DateTimeOffset WindowEnd => WindowStart + Window;
    }

    private readonly ConcurrentDictionary<Guid, Entry> _entries = new();
    private readonly TimeProvider _time;
    private readonly ILogger _audit;
    private long _lastSweepTicks;

    public AuthorizationDenialTracker(TimeProvider time, ILoggerFactory loggerFactory)
    {
        _time = time;
        _audit = loggerFactory.CreateLogger("Audit");
        _lastSweepTicks = time.GetUtcNow().UtcTicks;
    }

    /// <summary>Кількість partition у пам'яті (для тесту вилучення).</summary>
    public int PartitionCount => _entries.Count;

    /// <summary>Лише для тестів: очищає лічильники, щоб тести не впливали один на одного.</summary>
    public void Reset() => _entries.Clear();

    /// <summary>Скільки ще діє блокування для subject; null, якщо не заблоковано.</summary>
    public TimeSpan? GetRetryAfter(Guid subject)
    {
        var now = _time.GetUtcNow();
        Sweep(now);

        if (!_entries.TryGetValue(subject, out var entry))
            return null;

        lock (entry.Gate)
        {
            if (entry.Removed || now >= entry.WindowEnd)
                return null;

            return entry.Blocked ? entry.WindowEnd - now : null;
        }
    }

    /// <summary>Записує audit-запис authorization.denied; на 5-й відмові один раз за вікно пише burst.</summary>
    public void RecordDenial(Guid subject, string action, string resource, int statusCode, string traceId)
    {
        var now = _time.GetUtcNow();
        Sweep(now);

        bool burst;
        int count;
        DateTimeOffset windowEnd;

        while (true)
        {
            var entry = _entries.GetOrAdd(subject, _ => new Entry());
            lock (entry.Gate)
            {
                if (entry.Removed)
                    continue; // partition вилучено паралельно, беремо нову

                if (entry.Count == 0 || now >= entry.WindowEnd)
                {
                    entry.WindowStart = now;
                    entry.Count = 0;
                    entry.Blocked = false;
                    entry.BurstLogged = false;
                }

                entry.Count++;
                if (entry.Count >= Threshold)
                    entry.Blocked = true;

                burst = entry.Blocked && !entry.BurstLogged;
                if (burst)
                    entry.BurstLogged = true;

                count = entry.Count;
                windowEnd = entry.WindowEnd;
            }
            break;
        }

        _audit.LogInformation(
            "Audit {EventType}: subject {Subject}, action {Action}, resource {Resource}, result {Result}, time {Time}, traceId {TraceId}",
            "authorization.denied", subject, action, resource,
            statusCode == StatusCodes.Status403Forbidden ? "forbidden" : "not-found",
            now, traceId);

        if (burst)
        {
            _audit.LogWarning(
                "Security event {EventType}: subject {Subject}, denials {Count}, windowSeconds {WindowSeconds}, blockedUntil {BlockedUntil}, traceId {TraceId}",
                "authorization.denied.burst", subject, count, (int)Window.TotalSeconds, windowEnd, traceId);
        }
    }

    // Вилучення прострочених partition: не частіше за раз на вікно.
    private void Sweep(DateTimeOffset now)
    {
        var last = Interlocked.Read(ref _lastSweepTicks);
        if (now.UtcTicks - last < Window.Ticks)
            return;
        if (Interlocked.CompareExchange(ref _lastSweepTicks, now.UtcTicks, last) != last)
            return;

        foreach (var pair in _entries)
        {
            var entry = pair.Value;
            lock (entry.Gate)
            {
                if (now >= entry.WindowEnd)
                {
                    entry.Removed = true;
                    _entries.TryRemove(pair);
                }
            }
        }
    }
}
