namespace CvAi.Application.DTOs.Authentication;

public sealed class LogoutRequestDto
{
    public string RefreshToken { get; init; } = string.Empty;
}
