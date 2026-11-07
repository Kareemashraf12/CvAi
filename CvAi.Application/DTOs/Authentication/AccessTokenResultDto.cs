namespace CvAi.Application.DTOs.Authentication;

public sealed class AccessTokenResultDto
{
    public string Token { get; init; } = string.Empty;

    public DateTime ExpiresAtUtc { get; init; }
}