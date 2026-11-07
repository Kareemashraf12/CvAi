namespace CvAi.Application.DTOs.Authentication;

public sealed class LoginResponseDto
{
    public string AccessToken { get; init; } = string.Empty;

    public DateTime AccessTokenExpiresAtUtc { get; init; }

    public string RefreshToken { get; init; } = string.Empty;

    public DateTime RefreshTokenExpiresAtUtc { get; init; }

    public string UserId { get; init; } = string.Empty;

    public string FullName { get; init; } = string.Empty;

    public string Email { get; init; } = string.Empty;

    public string? ProfileImageUrl { get; init; }

    public IReadOnlyList<string> Roles { get; init; } = [];
}