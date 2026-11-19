namespace CvAi.Application.Common.Settings;

public sealed class PasswordResetSettings
{
    public const string SectionName = "PasswordReset";

    public int CodeExpirationMinutes { get; set; } = 15;

    public int ResendCooldownSeconds { get; set; } = 60;

    public int MaxAttempts { get; set; } = 5;
}
