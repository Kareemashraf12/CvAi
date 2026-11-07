using CvAi.Application.Abstractions.Authentication;
using CvAi.Application.Common.Models;
using CvAi.Application.DTOs.Authentication;
using CvAi.Infrastructure.Identity;
using Microsoft.AspNetCore.Identity;

namespace CvAi.Infrastructure.Identity.Services;

/// <summary>
/// Login and token refresh live here. The registration / OTP flow is
/// delegated to <see cref="IPendingRegistrationService"/> so that the logic
/// exists in exactly one place.
/// </summary>
public sealed class AuthenticationService : IAuthenticationService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IJwtTokenService _jwtTokenService;
    private readonly IRefreshTokenService _refreshTokenService;
    private readonly IPendingRegistrationService _pendingRegistrationService;

    public AuthenticationService(
        UserManager<ApplicationUser> userManager,
        IJwtTokenService jwtTokenService,
        IRefreshTokenService refreshTokenService,
        IPendingRegistrationService pendingRegistrationService)
    {
        _userManager = userManager;
        _jwtTokenService = jwtTokenService;
        _refreshTokenService = refreshTokenService;
        _pendingRegistrationService = pendingRegistrationService;
    }

    // ---------------------------------------------------------------
    // Registration flow (delegated)
    // ---------------------------------------------------------------

    public Task<ApiResponse<RegisterResponseDto>> RegisterAsync(
        RegisterRequestDto request,
        CancellationToken cancellationToken = default)
    {
        return _pendingRegistrationService.RegisterAsync(
            request,
            cancellationToken);
    }

    public Task<ApiResponse<RegisterResponseDto>> SendOtpAsync(
        SendOtpRequestDto request,
        CancellationToken cancellationToken = default)
    {
        // Sending an OTP for an existing pending registration is a resend.
        return _pendingRegistrationService.ResendOtpAsync(
            new ResendEmailOtpRequestDto { Email = request.Email },
            cancellationToken);
    }

    public Task<ApiResponse<RegisterResponseDto>> ResendOtpAsync(
        ResendEmailOtpRequestDto request,
        CancellationToken cancellationToken = default)
    {
        return _pendingRegistrationService.ResendOtpAsync(
            request,
            cancellationToken);
    }

    public Task<ApiResponse> VerifyEmailAsync(
        VerifyEmailOtpRequestDto request,
        CancellationToken cancellationToken = default)
    {
        return _pendingRegistrationService.VerifyEmailAsync(
            request,
            cancellationToken);
    }

    // ---------------------------------------------------------------
    // Login
    // ---------------------------------------------------------------

    public async Task<ApiResponse<LoginResponseDto>> LoginAsync(
        LoginRequestDto request,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(request.Email) ||
            string.IsNullOrWhiteSpace(request.Password) ||
            string.IsNullOrWhiteSpace(request.DeviceId))
        {
            return ApiResponse<LoginResponseDto>.Fail(
                "Email, password, and device ID are required.");
        }

        var email = request.Email.Trim();

        var user = await _userManager.FindByEmailAsync(email);

        if (user is null)
        {
            return ApiResponse<LoginResponseDto>.Fail(
                "Invalid email or password.");
        }

        if (await _userManager.IsLockedOutAsync(user))
        {
            return ApiResponse<LoginResponseDto>.Fail(
                "Your account is temporarily locked. Please try again later.");
        }

        var passwordValid = await _userManager.CheckPasswordAsync(
            user,
            request.Password);

        if (!passwordValid)
        {
            await _userManager.AccessFailedAsync(user);

            return ApiResponse<LoginResponseDto>.Fail(
                "Invalid email or password.");
        }

        await _userManager.ResetAccessFailedCountAsync(user);

        if (!user.EmailConfirmed)
        {
            return ApiResponse<LoginResponseDto>.Fail(
                "Your email is not verified. Please verify your email first.");
        }

        // Create the session first: if the device limit is reached,
        // no access token is generated for nothing.
        RefreshTokenResultDto refreshToken;

        try
        {
            refreshToken = await _refreshTokenService.CreateAsync(
                new CreateRefreshTokenDto
                {
                    UserId = user.Id,
                    DeviceId = request.DeviceId.Trim(),
                    DeviceName = request.DeviceName,
                    DeviceType = request.DeviceType
                },
                cancellationToken);
        }
        catch (InvalidOperationException ex)
        {
            return ApiResponse<LoginResponseDto>.Fail(ex.Message);
        }

        var accessToken = await _jwtTokenService.GenerateAccessTokenAsync(
            user.Id,
            cancellationToken);

        var roles = await _userManager.GetRolesAsync(user);

        var response = new LoginResponseDto
        {
            UserId = user.Id,
            FullName = user.FullName,
            Email = user.Email ?? string.Empty,
            AccessToken = accessToken.Token,
            AccessTokenExpiresAtUtc = accessToken.ExpiresAtUtc,
            RefreshToken = refreshToken.Token,
            RefreshTokenExpiresAtUtc = refreshToken.ExpiresAtUtc,
            Roles = roles.ToList()
        };

        return ApiResponse<LoginResponseDto>.Ok(
            response,
            "Login successful.");
    }

    // ---------------------------------------------------------------
    // Refresh access token
    // ---------------------------------------------------------------

    public async Task<ApiResponse<RefreshAccessTokenResponseDto>> RefreshAccessTokenAsync(
        RefreshTokenRequestDto request,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(request.RefreshToken))
        {
            return ApiResponse<RefreshAccessTokenResponseDto>.Fail(
                "Refresh token is required.");
        }

        // Validate the refresh token and retrieve its owner.
        var tokenValidation = await _refreshTokenService.ValidateAsync(
            request.RefreshToken,
            cancellationToken);

        if (tokenValidation is null)
        {
            return ApiResponse<RefreshAccessTokenResponseDto>.Fail(
                "Invalid or expired refresh token.");
        }

        var user = await _userManager.FindByIdAsync(
            tokenValidation.UserId);

        if (user is null)
        {
            return ApiResponse<RefreshAccessTokenResponseDto>.Fail(
                "User account was not found.");
        }

        if (!user.EmailConfirmed)
        {
            return ApiResponse<RefreshAccessTokenResponseDto>.Fail(
                "Your email address is not verified.");
        }

        if (await _userManager.IsLockedOutAsync(user))
        {
            return ApiResponse<RefreshAccessTokenResponseDto>.Fail(
                "Your account is temporarily locked.");
        }

        // Generate a new access token without rotating the refresh token.
        var accessToken = await _jwtTokenService.GenerateAccessTokenAsync(
            user.Id,
            cancellationToken);

        var response = new RefreshAccessTokenResponseDto
        {
            AccessToken = accessToken.Token,
            AccessTokenExpiresAtUtc = accessToken.ExpiresAtUtc
        };

        return ApiResponse<RefreshAccessTokenResponseDto>.Ok(
            response,
            "Access token refreshed successfully.");
    }
}