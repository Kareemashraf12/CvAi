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

public sealed class PendingRegistrationService : IPendingRegistrationService
{
    private const string DefaultRole = "User";

    private readonly ApplicationDbContext _context;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IPasswordHasher<ApplicationUser> _passwordHasher;
    private readonly IOtpService _otpService;
    private readonly IEmailService _emailService;
    private readonly PendingRegistrationSettings _settings;
    private readonly ILogger<PendingRegistrationService> _logger;

    public PendingRegistrationService(
        ApplicationDbContext context,
        UserManager<ApplicationUser> userManager,
        IPasswordHasher<ApplicationUser> passwordHasher,
        IOtpService otpService,
        IEmailService emailService,
        PendingRegistrationSettings settings,
        ILogger<PendingRegistrationService> logger)
    {
        _context = context;
        _userManager = userManager;
        _passwordHasher = passwordHasher;
        _otpService = otpService;
        _emailService = emailService;
        _settings = settings;
        _logger = logger;
    }

    public async Task<ApiResponse<RegisterResponseDto>> RegisterAsync(
        RegisterRequestDto request,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(request.FullName) ||
            string.IsNullOrWhiteSpace(request.Email) ||
            string.IsNullOrWhiteSpace(request.Password) ||
            string.IsNullOrWhiteSpace(request.ConfirmPassword))
        {
            return ApiResponse<RegisterResponseDto>.Fail(
                "All registration fields are required.");
        }

        if (!string.Equals(
                request.Password,
                request.ConfirmPassword,
                StringComparison.Ordinal))
        {
            return ApiResponse<RegisterResponseDto>.Fail(
                "Password and confirmation password do not match.");
        }

        var email = request.Email.Trim();
        var normalizedEmail = _userManager.NormalizeEmail(email);

        var existingUser = await _userManager.FindByEmailAsync(email);

        if (existingUser is not null)
        {
            return ApiResponse<RegisterResponseDto>.Fail(
                "An account with this email already exists.");
        }

        var now = DateTime.UtcNow;

        var pending = await _context.PendingRegistrations
            .FirstOrDefaultAsync(
                x => x.NormalizedEmail == normalizedEmail,
                cancellationToken);

        var isExpired = pending is not null && pending.ExpiresAtUtc <= now;

        // A live pending registration being submitted again is treated as
        // a resend: it obeys the same cooldown and the same resend limit,
        // otherwise Register could be used to bypass both.
        var isResubmission = pending is not null && !isExpired;

        if (isResubmission)
        {
            if (pending!.LastOtpSentAtUtc.HasValue &&
                now < pending.LastOtpSentAtUtc.Value.AddSeconds(
                    _settings.OtpResendCooldownSeconds))
            {
                return ApiResponse<RegisterResponseDto>.Fail(
                    "A verification code was recently sent. Please wait before trying again.");
            }

            if (pending.ResendCount >= _settings.MaxOtpResendCount)
            {
                return ApiResponse<RegisterResponseDto>.Fail(
                    "Maximum verification code requests reached. " +
                    "Please use the last code you received or try again later.");
            }
        }

        var temporaryUser = new ApplicationUser
        {
            FullName = request.FullName.Trim(),
            Email = email,
            UserName = email
        };

        foreach (var passwordValidator in _userManager.PasswordValidators)
        {
            var validationResult = await passwordValidator.ValidateAsync(
                _userManager,
                temporaryUser,
                request.Password);

            if (!validationResult.Succeeded)
            {
                var errors = string.Join(
                    " ",
                    validationResult.Errors.Select(x => x.Description));

                return ApiResponse<RegisterResponseDto>.Fail(errors);
            }
        }

        var otp = _otpService.GenerateOtp();

        if (pending is null)
        {
            pending = new PendingRegistration
            {
                Id = Guid.NewGuid(),
                CreatedAtUtc = now,
                ExpiresAtUtc = now.AddHours(
                    _settings.RegistrationExpirationHours),
                ResendCount = 0
            };

            await _context.PendingRegistrations.AddAsync(
                pending,
                cancellationToken);
        }
        else if (isExpired)
        {
            // Start a fresh registration window.
            pending.CreatedAtUtc = now;
            pending.ExpiresAtUtc = now.AddHours(
                _settings.RegistrationExpirationHours);
            pending.ResendCount = 0;
            pending.LastOtpSentAtUtc = null;
        }

        // Note: ExpiresAtUtc of a live registration is NOT extended here.
        pending.FullName = request.FullName.Trim();
        pending.Email = email;
        pending.NormalizedEmail = normalizedEmail!;
        pending.PasswordHash = _passwordHasher.HashPassword(
            temporaryUser,
            request.Password);

        pending.OtpHash = _otpService.HashOtp(otp);
        pending.OtpExpiresAtUtc = now.AddMinutes(
            _settings.OtpExpirationMinutes);
        pending.OtpAttempts = 0;

        // A failed email delivery must not delete the pending registration.
        await _context.SaveChangesAsync(cancellationToken);

        try
        {
            await _emailService.SendEmailAsync(
                email,
                "Verify your email address",
                $"Your CvAi verification code is: {otp}\n" +
                $"This code expires in {_settings.OtpExpirationMinutes} minutes.",
                cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(
                ex,
                "Failed to send verification email for pending registration {PendingRegistrationId}.",
                pending.Id);

            return ApiResponse<RegisterResponseDto>.Fail(
                "Your registration was saved, but the verification email could not be sent. Please try again later.");
        }

        pending.LastOtpSentAtUtc = DateTime.UtcNow;

        if (isResubmission)
        {
            pending.ResendCount++;
        }

        await _context.SaveChangesAsync(cancellationToken);

        var sentAt = pending.LastOtpSentAtUtc.Value;

        return ApiResponse<RegisterResponseDto>.Ok(
            new RegisterResponseDto
            {
                Email = pending.Email,
                OtpExpiresAtUtc = pending.OtpExpiresAtUtc,
                ResendAvailableAtUtc = sentAt.AddSeconds(
                    _settings.OtpResendCooldownSeconds)
            },
            "Registration saved. Please check your email for the verification code.");
    }

    public async Task<ApiResponse> VerifyEmailAsync(
        VerifyEmailOtpRequestDto request,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(request.Email) ||
            string.IsNullOrWhiteSpace(request.Otp))
        {
            return ApiResponse.Fail(
                "Email and verification code are required.");
        }

        var normalizedEmail = _userManager.NormalizeEmail(
            request.Email.Trim());

        var pending = await _context.PendingRegistrations
            .FirstOrDefaultAsync(
                x => x.NormalizedEmail == normalizedEmail,
                cancellationToken);

        if (pending is null)
        {
            return ApiResponse.Fail(
                "Registration not found or expired.");
        }

        var now = DateTime.UtcNow;

        if (pending.ExpiresAtUtc <= now)
        {
            _context.PendingRegistrations.Remove(pending);
            await _context.SaveChangesAsync(cancellationToken);

            return ApiResponse.Fail(
                "Registration has expired. Please register again.");
        }

        if (pending.OtpAttempts >= _settings.MaxOtpAttempts)
        {
            return ApiResponse.Fail(
                "Maximum verification attempts reached. Request a new code.");
        }

        if (pending.OtpExpiresAtUtc <= now)
        {
            return ApiResponse.Fail(
                "Verification code has expired. Request a new code.");
        }

        if (!_otpService.VerifyOtp(request.Otp.Trim(), pending.OtpHash))
        {
            pending.OtpAttempts++;

            if (pending.OtpAttempts >= _settings.MaxOtpAttempts)
            {
                // Invalidate the code once the attempts are exhausted.
                pending.OtpExpiresAtUtc = now;
            }

            await _context.SaveChangesAsync(cancellationToken);

            return ApiResponse.Fail(
                "Invalid verification code.");
        }

        var existingUser = await _userManager.FindByEmailAsync(
            pending.Email);

        if (existingUser is not null)
        {
            _context.PendingRegistrations.Remove(pending);
            await _context.SaveChangesAsync(cancellationToken);

            return ApiResponse.Fail(
                "An account with this email already exists.");
        }

        // If anything below fails, disposing the transaction rolls it back.
        await using var transaction =
            await _context.Database.BeginTransactionAsync(
                cancellationToken);

        var user = new ApplicationUser
        {
            Id = Guid.NewGuid().ToString(),
            FullName = pending.FullName,
            Email = pending.Email,
            UserName = pending.Email,
            NormalizedEmail = pending.NormalizedEmail,
            NormalizedUserName = _userManager.NormalizeName(
                pending.Email),
            EmailConfirmed = true,
            PasswordHash = pending.PasswordHash
        };

        var creationResult = await _userManager.CreateAsync(user);

        if (!creationResult.Succeeded)
        {
            return ApiResponse.Fail(
                string.Join(
                    " ",
                    creationResult.Errors.Select(x => x.Description)));
        }

        // The default role was previously assigned only by AuthenticationService.
        // It must be assigned here, because this is where users are created.
        var roleResult = await _userManager.AddToRoleAsync(user, DefaultRole);

        if (!roleResult.Succeeded)
        {
            return ApiResponse.Fail(
                "Unable to assign the default role: " +
                string.Join(
                    " ",
                    roleResult.Errors.Select(x => x.Description)));
        }

        _context.PendingRegistrations.Remove(pending);

        await _context.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return ApiResponse.Ok(
            "Email verified and account created successfully.");
    }

    public async Task<ApiResponse<RegisterResponseDto>> ResendOtpAsync(
        ResendEmailOtpRequestDto request,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(request.Email))
        {
            return ApiResponse<RegisterResponseDto>.Fail(
                "Email is required.");
        }

        var normalizedEmail = _userManager.NormalizeEmail(
            request.Email.Trim());

        var pending = await _context.PendingRegistrations
            .FirstOrDefaultAsync(
                x => x.NormalizedEmail == normalizedEmail,
                cancellationToken);

        var now = DateTime.UtcNow;

        if (pending is null || pending.ExpiresAtUtc <= now)
        {
            return ApiResponse<RegisterResponseDto>.Fail(
                "Registration not found or expired. Please register again.");
        }

        if (pending.LastOtpSentAtUtc.HasValue)
        {
            var resendAvailableAt = pending.LastOtpSentAtUtc.Value
                .AddSeconds(_settings.OtpResendCooldownSeconds);

            if (now < resendAvailableAt)
            {
                return ApiResponse<RegisterResponseDto>.Fail(
                    "Please wait before requesting another verification code.");
            }
        }

        if (pending.ResendCount >= _settings.MaxOtpResendCount)
        {
            return ApiResponse<RegisterResponseDto>.Fail(
                "Maximum resend attempts reached.");
        }

        var otp = _otpService.GenerateOtp();

        pending.OtpHash = _otpService.HashOtp(otp);
        pending.OtpExpiresAtUtc = now.AddMinutes(
            _settings.OtpExpirationMinutes);

        pending.OtpAttempts = 0;

        // Save the new hash first. If email delivery fails,
        // the pending registration remains available for retry.
        await _context.SaveChangesAsync(cancellationToken);

        try
        {
            await _emailService.SendEmailAsync(
                pending.Email,
                "Your new CvAi verification code",
                $"Your new verification code is: {otp}\n" +
                $"This code expires in {_settings.OtpExpirationMinutes} minutes.",
                cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(
                ex,
                "Failed to resend verification email for pending registration {PendingRegistrationId}.",
                pending.Id);

            return ApiResponse<RegisterResponseDto>.Fail(
                "The verification email could not be sent. Please try again later.");
        }

        pending.LastOtpSentAtUtc = DateTime.UtcNow;
        pending.ResendCount++;

        await _context.SaveChangesAsync(cancellationToken);

        var sentAt = pending.LastOtpSentAtUtc.Value;

        return ApiResponse<RegisterResponseDto>.Ok(
            new RegisterResponseDto
            {
                Email = pending.Email,
                OtpExpiresAtUtc = pending.OtpExpiresAtUtc,
                ResendAvailableAtUtc = sentAt.AddSeconds(
                    _settings.OtpResendCooldownSeconds)
            },
            "A new verification code has been sent.");
    }
}