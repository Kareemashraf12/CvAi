using CvAi.Application.DTOs.Authentication;

namespace CvAi.Application.Abstractions.Authentication;

public interface IJwtTokenService
{
    Task<AccessTokenResultDto> GenerateAccessTokenAsync(
        string userId,
        CancellationToken cancellationToken = default);
}