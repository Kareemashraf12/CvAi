namespace CvAi.Application.DTOs.Authentication;

public sealed class RefreshTokenRotationResultDto
{
    public RefreshTokenRotationStatus Status { get; init; }

    public RefreshTokenResultDto? NewToken { get; init; }

    /// <summary>Owner of the presented token, when it was found in the database.</summary>
    public string UserId { get; init; } = string.Empty;

    public string DeviceId { get; init; } = string.Empty;
}
