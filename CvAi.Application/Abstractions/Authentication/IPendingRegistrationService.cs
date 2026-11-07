using CvAi.Application.Common.Models;
using CvAi.Application.DTOs.Authentication;

namespace CvAi.Application.Abstractions.Authentication;

public interface IPendingRegistrationService
{
    Task<ApiResponse<RegisterResponseDto>> RegisterAsync(
        RegisterRequestDto request,
        CancellationToken cancellationToken = default);

    Task<ApiResponse> VerifyEmailAsync(
        VerifyEmailOtpRequestDto request,
        CancellationToken cancellationToken = default);

    Task<ApiResponse<RegisterResponseDto>> ResendOtpAsync(
        ResendEmailOtpRequestDto request,
        CancellationToken cancellationToken = default);
}