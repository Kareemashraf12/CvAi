namespace CvAi.Application.DTOs.Authentication;

public sealed class SendOtpRequestDto
{
    public string Email { get; init; } = string.Empty;
}