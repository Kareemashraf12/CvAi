namespace CvAi.Application.DTOs.Authentication;

public sealed class RefreshAccessTokenResponseDto
{
    public string AccessToken { get; init; } = string.Empty;

    public DateTime AccessTokenExpiresAtUtc { get; init; }
}