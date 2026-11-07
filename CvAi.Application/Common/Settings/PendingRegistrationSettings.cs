namespace CvAi.Application.Common.Settings;

public sealed class PendingRegistrationSettings
{
    public const string SectionName = "PendingRegistration";

    public string OtpHashSecret { get; set; } = string.Empty;

    public int RegistrationExpirationHours { get; set; } = 24;

    public int OtpLength { get; set; } = 6;

    public int OtpExpirationMinutes { get; set; } = 5;

    public int OtpResendCooldownSeconds { get; set; } = 60;

    public int MaxOtpAttempts { get; set; } = 5;

    public int MaxOtpResendCount { get; set; } = 5;
}