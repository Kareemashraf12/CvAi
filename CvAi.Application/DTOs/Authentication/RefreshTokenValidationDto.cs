namespace CvAi.Application.DTOs.Authentication;

public sealed class RefreshTokenValidationDto
{
    public string UserId { get; init; } = string.Empty;

    public string DeviceId { get; init; } = string.Empty;

    public DateTime ExpiresAtUtc { get; init; }
}