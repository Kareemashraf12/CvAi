namespace CvAi.Domain.Entities;

public sealed class PasswordReset
{
    public Guid Id { get; set; }

    public string UserId { get; set; } = string.Empty;

    public string Email { get; set; } = string.Empty;

    public string NormalizedEmail { get; set; } = string.Empty;

    public string CodeHash { get; set; } = string.Empty;

    public DateTime CreatedAtUtc { get; set; }

    public DateTime ExpiresAtUtc { get; set; }

    public DateTime? LastCodeSentAtUtc { get; set; }

    public int Attempts { get; set; }

    public DateTime? UsedAtUtc { get; set; }
}
