namespace CvAi.Application.DTOs.Authentication;

public sealed class LoginRequestDto
{
    public string Email { get; init; } = string.Empty;

    public string Password { get; init; } = string.Empty;

    public string DeviceId { get; init; } = string.Empty;

    public string? DeviceName { get; init; }

    public string? DeviceType { get; init; }
}