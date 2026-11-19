namespace CvAi.Application.DTOs.Authentication;

public sealed class RefreshAccessTokenResponseDto
{
    public string AccessToken { get; init; } = string.Empty;

    public DateTime AccessTokenExpiresAtUtc { get; init; }


    public string RefreshToken { get; init; } = string.Empty;

    public DateTime RefreshTokenExpiresAtUtc { get; init; }
}
