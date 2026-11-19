using CvAi.Application.Abstractions.Authentication;
using CvAi.Application.Abstractions.Email;
using CvAi.Application.Common.Models;
using CvAi.Application.Common.Settings;
using CvAi.Application.DTOs.Authentication;
using CvAi.Domain.Entities;
using CvAi.Infrastructure.Identity;
using CvAi.Infrastructure.Persistence;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace CvAi.Infrastructure.Identity.Services;

public sealed class PasswordResetService : IPasswordResetService
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IOtpService _otpService;
    private readonly IEmailService _emailService;
    private readonly IRefreshTokenService _refreshTokenService;
    private readonly PasswordResetSettings _settings;
    private readonly ILogger<PasswordResetService> _logger;

    public PasswordResetService(
        ApplicationDbContext context,
        UserManager<ApplicationUser> userManager,
        IOtpService otpService,
        IEmailService emailService,
        IRefreshTokenService refreshTokenService,
        PasswordResetSettings settings,
        ILogger<PasswordResetService> logger)
    {
        _context = context;
        _userManager = userManager;
        _otpService = otpService;
        _emailService = emailService;
        _refreshTokenService = refreshTokenService;
        _settings = settings;
        _logger = logger;
    }

    // The same generic response is used for every outcome, so the endpoint
    // never reveals whether an account exists.
    private static readonly ApiResponse GenericOk = ApiResponse.Ok(
        " a password reset code has been sent.");

    public async Task<ApiResponse> RequestResetAsync(
        ForgotPasswordRequestDto request,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(request.Email))
        {
            return ApiResponse.Fail("Email is required.");
        }

        var email = request.Email.Trim();
        var normalizedEmail = _userManager.NormalizeEmail(email);

        var user = await _userManager.FindByEmailAsync(email);

        // Unknown account or unverified email: stay silent.
        if (user is null || !user.EmailConfirmed)
        {
            return GenericOk;
        }

        var now = DateTime.UtcNow;

        var row = await _context.PasswordResets
            .FirstOrDefaultAsync(x => x.UserId == user.Id, cancellationToken);

        // A live code that was recently sent is not replaced: the resend
        // cooldown applies regardless of how often the endpoint is called.
        if (row is not null &&
            row.UsedAtUtc is null &&
            row.ExpiresAtUtc > now &&
            row.LastCodeSentAtUtc is not null &&
            now < row.LastCodeSentAtUtc.Value.AddSeconds(
                _settings.ResendCooldownSeconds))
        {
            return GenericOk;
        }

        var code = _otpService.GenerateOtp();

        if (row is null)
        {
            row = new PasswordReset
            {
                Id = Guid.NewGuid(),
                UserId = user.Id,
                CreatedAtUtc = now
            };

            await _context.PasswordResets.AddAsync(row, cancellationToken);
        }

        row.Email = email;
        row.NormalizedEmail = normalizedEmail ?? string.Empty;
        row.CodeHash = _otpService.HashOtp(code);
        row.ExpiresAtUtc = now.AddMinutes(_settings.CodeExpirationMinutes);
        row.Attempts = 0;
        row.UsedAtUtc = null;

        // Persist the hash before sending: a failed delivery leaves the
        // request retryable and does not start the cooldown clock.
        await _context.SaveChangesAsync(cancellationToken);

        try
        {
            await _emailService.SendEmailAsync(
                email,
                "Your CvAi password reset code",
                $"Your password reset code is: {code}\n" +
                $"This code expires in {_settings.CodeExpirationMinutes} minutes.\n" +
                "If you did not request a password reset, you can ignore this email.",
                cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(
                ex,
                "Failed to send password reset email for user {UserId}.",
                user.Id);

            // The response stays generic: no signal to the caller either way.
            return GenericOk;
        }

        row.LastCodeSentAtUtc = DateTime.UtcNow;

        await _context.SaveChangesAsync(cancellationToken);

        return GenericOk;
    }

    public async Task<ApiResponse> ResetPasswordAsync(
        ResetPasswordRequestDto request,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(request.Email) ||
            string.IsNullOrWhiteSpace(request.Code) ||
            string.IsNullOrWhiteSpace(request.NewPassword) ||
            string.IsNullOrWhiteSpace(request.ConfirmPassword))
        {
            return ApiResponse.Fail(
                "Email, verification code, and the new password are required.");
        }

        if (!string.Equals(
                request.NewPassword,
                request.ConfirmPassword,
                StringComparison.Ordinal))
        {
            return ApiResponse.Fail(
                "The new password and confirmation password do not match.");
        }

        var normalizedEmail = _userManager.NormalizeEmail(
            request.Email.Trim());

        var row = await _context.PasswordResets
            .FirstOrDefaultAsync(
                x => x.NormalizedEmail == normalizedEmail,
                cancellationToken);

        // One generic message for every failure below: it must not help an
        // attacker distinguish between "no request", "bad code", "expired".
        const string genericFail =
            "Invalid or expired reset code. Please request a new one.";

        var now = DateTime.UtcNow;

        if (row is null)
        {
            return ApiResponse.Fail(genericFail);
        }

        if (row.UsedAtUtc is not null || row.ExpiresAtUtc <= now)
        {
            return ApiResponse.Fail(genericFail);
        }

        if (row.Attempts >= _settings.MaxAttempts)
        {
            return ApiResponse.Fail(
                "Maximum reset attempts reached. Please request a new code.");
        }

        if (!_otpService.VerifyOtp(request.Code.Trim(), row.CodeHash))
        {
            row.Attempts++;

            if (row.Attempts >= _settings.MaxAttempts)
            {
                // Invalidate the code once the attempts are exhausted.
                row.ExpiresAtUtc = now;
            }

            await _context.SaveChangesAsync(cancellationToken);

            return ApiResponse.Fail(genericFail);
        }

        var user = await _userManager.FindByIdAsync(row.UserId);

        if (user is null)
        {
            _context.PasswordResets.Remove(row);
            await _context.SaveChangesAsync(cancellationToken);

            return ApiResponse.Fail(genericFail);
        }

        // Run the password validators explicitly so that a policy violation
        // is reported before the reset code is consumed.
        foreach (var passwordValidator in _userManager.PasswordValidators)
        {
            var validationResult = await passwordValidator.ValidateAsync(
                _userManager,
                user,
                request.NewPassword);

            if (!validationResult.Succeeded)
            {
                var errors = string.Join(
                    " ",
                    validationResult.Errors.Select(x => x.Description));

                return ApiResponse.Fail(errors);
            }
        }

        // If anything below fails, disposing the transaction rolls it back.
        await using var transaction =
            await _context.Database.BeginTransactionAsync(cancellationToken);

        // Identity generates its own single-use token; we never persist it.
        var resetToken = await _userManager.GeneratePasswordResetTokenAsync(user);

        var resetResult = await _userManager.ResetPasswordAsync(
            user,
            resetToken,
            request.NewPassword);

        if (!resetResult.Succeeded)
        {
            return ApiResponse.Fail(
                string.Join(
                    " ",
                    resetResult.Errors.Select(x => x.Description)));
        }

        row.UsedAtUtc = DateTime.UtcNow;

        await _context.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        // The password has changed: every existing session is untrusted now.
        await _refreshTokenService.RevokeAllAsync(user.Id, cancellationToken);

        return ApiResponse.Ok(
            "Password has been reset successfully. Please log in again.");
    }
}
