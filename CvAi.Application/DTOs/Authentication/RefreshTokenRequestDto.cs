namespace CvAi.Application.DTOs.Authentication;

public sealed class RefreshTokenRequestDto
{
    public string RefreshToken { get; init; } = string.Empty;
}