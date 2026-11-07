namespace CvAi.Domain.Entities;

public sealed class PendingRegistration
{
    public Guid Id { get; set; }

    public string FullName { get; set; } = string.Empty;

    public string Email { get; set; } = string.Empty;

    public string NormalizedEmail { get; set; } = string.Empty;

    public string PasswordHash { get; set; } = string.Empty;

    public string OtpHash { get; set; } = string.Empty;

    public DateTime OtpExpiresAtUtc { get; set; }

    public DateTime CreatedAtUtc { get; set; }

    public DateTime ExpiresAtUtc { get; set; }

    public DateTime? LastOtpSentAtUtc { get; set; }

    public int OtpAttempts { get; set; }

    public int ResendCount { get; set; }
}