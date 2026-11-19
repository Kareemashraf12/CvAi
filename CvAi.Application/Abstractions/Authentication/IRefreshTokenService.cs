using CvAi.Application.DTOs.Authentication;

namespace CvAi.Application.Abstractions.Authentication;

public interface IRefreshTokenService
{
    Task<RefreshTokenResultDto> CreateAsync(
        CreateRefreshTokenDto request,
        CancellationToken cancellationToken = default);


    Task<RefreshTokenRotationResultDto> RotateAsync(
        string token,
        CancellationToken cancellationToken = default);


    Task<bool> RevokeByTokenAsync(
        string token,
        CancellationToken cancellationToken = default);

    Task<bool> RevokeAsync(
        string userId,
        string deviceId,
        CancellationToken cancellationToken = default);

    Task RevokeAllAsync(
        string userId,
        CancellationToken cancellationToken = default);
}
