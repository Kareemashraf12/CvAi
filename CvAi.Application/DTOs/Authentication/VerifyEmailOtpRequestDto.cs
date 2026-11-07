namespace CvAi.Application.DTOs.Authentication;

public sealed class VerifyEmailOtpRequestDto
{
    public string Email { get; init; } = string.Empty;

    public string Otp { get; init; } = string.Empty;
}