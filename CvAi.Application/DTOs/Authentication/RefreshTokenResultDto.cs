namespace CvAi.Application.DTOs.Authentication;

public sealed class RefreshTokenResultDto
{
    public string Token { get; init; } = string.Empty;

    public DateTime ExpiresAtUtc { get; init; }
}