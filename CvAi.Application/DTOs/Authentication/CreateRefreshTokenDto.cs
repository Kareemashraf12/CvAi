namespace CvAi.Application.DTOs.Authentication;

public sealed class CreateRefreshTokenDto
{
    public string UserId { get; init; } = string.Empty;

    public string DeviceId { get; init; } = string.Empty;

    public string? DeviceName { get; init; }

    public string? DeviceType { get; init; }
}