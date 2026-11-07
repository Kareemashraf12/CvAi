namespace CvAi.Application.DTOs.Authentication;

public sealed class RegisterResponseDto
{
    public string Email { get; init; } = string.Empty;

    public DateTime OtpExpiresAtUtc { get; init; }

    public DateTime ResendAvailableAtUtc { get; init; }
}