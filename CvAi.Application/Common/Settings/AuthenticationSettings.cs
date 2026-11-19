namespace CvAi.Application.Common.Settings;

public sealed class AuthenticationSettings
{
    public const string SectionName = "Authentication";

    public int MaxActiveDevices { get; set; } = 5;

    /// <summary>
    /// Grace window (seconds) during which a just-rotated refresh token may
    /// still be redeemed. Covers clients that refresh concurrently (e.g.
    /// two app tabs) so the loser of the race is not treated as a thief.
    /// </summary>
    public int RefreshTokenReuseGraceSeconds { get; set; } = 30;
}