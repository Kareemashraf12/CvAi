using CvAi.Application.Abstractions.Authentication;
using CvAi.Application.Abstractions.Files;
using CvAi.Application.Common.Models;
using CvAi.Application.DTOs.Authentication;
using CvAi.Infrastructure.Identity;
using CvAi.Infrastructure.Persistence;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace CvAi.Infrastructure.Identity.Services;


public sealed class AuthenticationService : IAuthenticationService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IJwtTokenService _jwtTokenService;
    private readonly IRefreshTokenService _refreshTokenService;
    private readonly IPendingRegistrationService _pendingRegistrationService;
    private readonly ApplicationDbContext _context;
    private readonly IImageService _imageService;
    private readonly ILogger<AuthenticationService> _logger;

    public AuthenticationService(
        UserManager<ApplicationUser> userManager,
        IJwtTokenService jwtTokenService,
        IRefreshTokenService refreshTokenService,
        IPendingRegistrationService pendingRegistrationService,
        ApplicationDbContext context,
        IImageService imageService,
        ILogger<AuthenticationService> logger)
    {
        _userManager = userManager;
        _jwtTokenService = jwtTokenService;
        _refreshTokenService = refreshTokenService;
        _pendingRegistrationService = pendingRegistrationService;
        _context = context;
        _imageService = imageService;
        _logger = logger;
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
            request.DeviceId.Trim(),
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
    // Refresh access token (with refresh token rotation)
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

        var rotation = await _refreshTokenService.RotateAsync(
            request.RefreshToken,
            cancellationToken);

        if (rotation.Status == RefreshTokenRotationStatus.Reused ||
            rotation.Status == RefreshTokenRotationStatus.Invalid)
        {
            return ApiResponse<RefreshAccessTokenResponseDto>.Fail(
                "Invalid or expired refresh token.");
        }

        var user = await _userManager.FindByIdAsync(
            rotation.UserId);

        if (user is null)
        {
            await KillRotatedSessionAsync(rotation, cancellationToken);

            return ApiResponse<RefreshAccessTokenResponseDto>.Fail(
                "User account was not found.");
        }

        if (!user.EmailConfirmed)
        {
            await KillRotatedSessionAsync(rotation, cancellationToken);

            return ApiResponse<RefreshAccessTokenResponseDto>.Fail(
                "Your email address is not verified.");
        }

        if (await _userManager.IsLockedOutAsync(user))
        {
            await KillRotatedSessionAsync(rotation, cancellationToken);

            return ApiResponse<RefreshAccessTokenResponseDto>.Fail(
                "Your account is temporarily locked.");
        }

        var accessToken = await _jwtTokenService.GenerateAccessTokenAsync(
            user.Id,
            rotation.DeviceId,
            cancellationToken);

        var response = new RefreshAccessTokenResponseDto
        {
            AccessToken = accessToken.Token,
            AccessTokenExpiresAtUtc = accessToken.ExpiresAtUtc,
            RefreshToken = rotation.NewToken!.Token,
            RefreshTokenExpiresAtUtc = rotation.NewToken.ExpiresAtUtc
        };

        return ApiResponse<RefreshAccessTokenResponseDto>.Ok(
            response,
            "Access token refreshed successfully.");
    }


    private async Task KillRotatedSessionAsync(
        RefreshTokenRotationResultDto rotation,
        CancellationToken cancellationToken)
    {
        if (rotation.NewToken is not null)
        {
            await _refreshTokenService.RevokeByTokenAsync(
                rotation.NewToken.Token,
                cancellationToken);
        }
    }

    // ---------------------------------------------------------------
    // Logout
    // ---------------------------------------------------------------

    public async Task<ApiResponse> LogoutAsync(
        LogoutRequestDto request,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(request.RefreshToken))
        {
            return ApiResponse.Fail(
                "Refresh token is required.");
        }

        var revoked = await _refreshTokenService.RevokeByTokenAsync(
            request.RefreshToken,
            cancellationToken);

        return revoked
            ? ApiResponse.Ok("Logged out successfully.")
            : ApiResponse.Fail("Session not found or already ended.");
    }

    public async Task<ApiResponse> RevokeAllSessionsAsync(
        string userId,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(userId))
        {
            return ApiResponse.Fail(
                "User ID is required.");
        }

        await _refreshTokenService.RevokeAllAsync(
            userId,
            cancellationToken);

        return ApiResponse.Ok(
            "All sessions have been revoked.");
    }

    // ---------------------------------------------------------------
    // Delete account
    // ---------------------------------------------------------------

    public async Task<ApiResponse> DeleteAccountAsync(
        string userId,
        DeleteAccountRequestDto request,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(userId))
        {
            return ApiResponse.Fail("User ID is required.");
        }

        if (string.IsNullOrWhiteSpace(request.Password))
        {
            return ApiResponse.Fail(
                "Password is required to delete the account.");
        }

        var user = await _userManager.FindByIdAsync(userId);

        if (user is null)
        {
            return ApiResponse.Fail("User account was not found.");
        }

        if (await _userManager.IsLockedOutAsync(user))
        {
            return ApiResponse.Fail(
                "Your account is temporarily locked. Please try again later.");
        }

        var passwordValid = await _userManager.CheckPasswordAsync(
            user,
            request.Password);

        if (!passwordValid)
        {
        
            await _userManager.AccessFailedAsync(user);

            return ApiResponse.Fail("Incorrect password.");
        }

        await _userManager.ResetAccessFailedCountAsync(user);

        // If anything below fails, disposing the transaction rolls it back.
        await using var transaction =
            await _context.Database.BeginTransactionAsync(cancellationToken);


        await _context.RefreshTokens
            .Where(x => x.UserId == userId)
            .ExecuteDeleteAsync(cancellationToken);

        await _context.PasswordResets
            .Where(x => x.UserId == userId)
            .ExecuteDeleteAsync(cancellationToken);

        if (!string.IsNullOrWhiteSpace(user.Email))
        {
            var normalizedEmail = _userManager.NormalizeEmail(user.Email);

            await _context.PendingRegistrations
                .Where(x => x.NormalizedEmail == normalizedEmail)
                .ExecuteDeleteAsync(cancellationToken);
        }

        var deleteResult = await _userManager.DeleteAsync(user);

        if (!deleteResult.Succeeded)
        {
            return ApiResponse.Fail(
                string.Join(
                    " ",
                    deleteResult.Errors.Select(x => x.Description)));
        }

        await _context.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

   
        if (!string.IsNullOrWhiteSpace(user.ProfileImageKey))
        {
            try
            {
                await _imageService.DeleteAsync(
                    user.ProfileImageKey,
                    cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(
                    ex,
                    "Failed to delete the profile image {ImageKey} of deleted user {UserId}.",
                    user.ProfileImageKey,
                    userId);
            }
        }

        return ApiResponse.Ok(
            "Your account has been deleted successfully.");
    }
}