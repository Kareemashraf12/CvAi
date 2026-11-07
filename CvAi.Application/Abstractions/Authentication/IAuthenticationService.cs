using CvAi.Application.Common.Models;
using CvAi.Application.DTOs.Authentication;

namespace CvAi.Application.Abstractions.Authentication;

public interface IAuthenticationService
{
    Task<ApiResponse<RegisterResponseDto>> RegisterAsync(
        RegisterRequestDto request,
        CancellationToken cancellationToken = default);

    Task<ApiResponse<LoginResponseDto>> LoginAsync(
        LoginRequestDto request,
        CancellationToken cancellationToken = default);

    Task<ApiResponse<RefreshAccessTokenResponseDto>> RefreshAccessTokenAsync(
        RefreshTokenRequestDto request,
        CancellationToken cancellationToken = default);

    Task<ApiResponse<RegisterResponseDto>> SendOtpAsync(
        SendOtpRequestDto request,
        CancellationToken cancellationToken = default);

    Task<ApiResponse<RegisterResponseDto>> ResendOtpAsync(
        ResendEmailOtpRequestDto request,
        CancellationToken cancellationToken = default);

    Task<ApiResponse> VerifyEmailAsync(
        VerifyEmailOtpRequestDto request,
        CancellationToken cancellationToken = default);
}