using System.Security.Cryptography;
using System.Text;
using CvAi.Application.Abstractions.Authentication;
using CvAi.Application.Common.Settings;
using CvAi.Application.DTOs.Authentication;
using CvAi.Domain.Entities;
using CvAi.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace CvAi.Infrastructure.Identity.Services;

public sealed class RefreshTokenService : IRefreshTokenService
{
    private readonly ApplicationDbContext _context;
    private readonly JwtSettings _jwtSettings;
    private readonly AuthenticationSettings _authenticationSettings;
    private readonly ILogger<RefreshTokenService> _logger;

    public RefreshTokenService(
        ApplicationDbContext context,
        JwtSettings jwtSettings,
        AuthenticationSettings authenticationSettings,
        ILogger<RefreshTokenService> logger)
    {
        _context = context;
        _jwtSettings = jwtSettings;
        _authenticationSettings = authenticationSettings;
        _logger = logger;
    }

    public async Task<RefreshTokenResultDto> CreateAsync(
        CreateRefreshTokenDto request,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(request.UserId))
            throw new ArgumentException("User ID is required.");

        if (string.IsNullOrWhiteSpace(request.DeviceId))
            throw new ArgumentException("Device ID is required.");

        var deviceId = request.DeviceId.Trim();

        await using var transaction =
            await _context.Database.BeginTransactionAsync(
                System.Data.IsolationLevel.Serializable,
                cancellationToken);

        var now = DateTime.UtcNow;

        // Count the OTHER devices that currently have an active session.
        // The device that is logging in now must not count against the limit,
        // because its old session is replaced below.
        var otherActiveDevicesCount = await _context.RefreshTokens
            .Where(x =>
                x.UserId == request.UserId &&
                x.DeviceId != deviceId &&
                x.RevokedAtUtc == null &&
                x.ExpiresAtUtc > now)
            .Select(x => x.DeviceId)
            .Distinct()
            .CountAsync(cancellationToken);

        if (otherActiveDevicesCount >= _authenticationSettings.MaxActiveDevices)
        {
            throw new InvalidOperationException(
                "Maximum active devices limit reached.");
        }

        // Replace any previous session of the same device instead of
        // blocking the login (e.g. after reinstalling the app or losing the token).
        var previousSessions = await _context.RefreshTokens
            .Where(x =>
                x.UserId == request.UserId &&
                x.DeviceId == deviceId &&
                x.RevokedAtUtc == null)
            .ToListAsync(cancellationToken);

        foreach (var session in previousSessions)
        {
            session.RevokedAtUtc = now;
        }

        var rawToken = GenerateToken();

        var expiresAtUtc = now.AddDays(
            _jwtSettings.RefreshTokenExpirationDays);

        var entity = new RefreshToken
        {
            Id = Guid.NewGuid(),
            UserId = request.UserId,
            DeviceId = deviceId,
            DeviceName = request.DeviceName?.Trim(),
            DeviceType = request.DeviceType?.Trim(),
            TokenHash = HashToken(rawToken),
            CreatedAtUtc = now,
            LastUsedAtUtc = now,
            ExpiresAtUtc = expiresAtUtc
        };

        await _context.RefreshTokens.AddAsync(entity, cancellationToken);
        await _context.SaveChangesAsync(cancellationToken);

        await transaction.CommitAsync(cancellationToken);

        return new RefreshTokenResultDto
        {
            Token = rawToken,
            ExpiresAtUtc = expiresAtUtc
        };
    }

    public async Task<RefreshTokenRotationResultDto> RotateAsync(
        string token,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return new RefreshTokenRotationResultDto
            {
                Status = RefreshTokenRotationStatus.Invalid
            };
        }

        var tokenHash = HashToken(token);

        // The loop re-reads the row after losing a concurrent rotation.
        for (var attempt = 0; attempt < 3; attempt++)
        {
            var entity = await _context.RefreshTokens
                .AsNoTracking()
                .FirstOrDefaultAsync(
                    x => x.TokenHash == tokenHash,
                    cancellationToken);

            if (entity is null)
            {
                return new RefreshTokenRotationResultDto
                {
                    Status = RefreshTokenRotationStatus.Invalid
                };
            }

            var now = DateTime.UtcNow;

            // The token has been revoked before.
            if (entity.RevokedAtUtc is not null)
            {
                var graceEndsAt = entity.RevokedAtUtc.Value.AddSeconds(
                    _authenticationSettings.RefreshTokenReuseGraceSeconds);

                if (entity.ReplacedByTokenHash is not null)
                {
                    // The token was revoked by rotation. Presenting it again
                    // after the grace window is treated as theft: destroy
                    // every active session of the owner.
                    if (now > graceEndsAt)
                    {
                        _logger.LogWarning(
                            "Refresh token reuse detected (possible theft) for user {UserId}. Revoking all sessions.",
                            entity.UserId);

                        await RevokeAllAsync(entity.UserId, cancellationToken);

                        return new RefreshTokenRotationResultDto
                        {
                            Status = RefreshTokenRotationStatus.Reused,
                            UserId = entity.UserId,
                            DeviceId = entity.DeviceId
                        };
                    }

                    // Still inside the grace window: a concurrent refresh
                    // (e.g. two app tabs sharing one stored token) lost the
                    // race. Let it rotate again instead of forcing a re-login.
                    var graceRotated = await RotateCoreAsync(
                        entity,
                        tokenHash,
                        now,
                        withinGrace: true,
                        cancellationToken);

                    if (graceRotated is not null)
                        return graceRotated;

                    continue;
                }

                // Revoked without a replacement (logout, device limit,
                // revoke-all): a dead token, but not evidence of theft.
                return new RefreshTokenRotationResultDto
                {
                    Status = RefreshTokenRotationStatus.Invalid,
                    UserId = entity.UserId,
                    DeviceId = entity.DeviceId
                };
            }

            // Expired tokens cannot be redeemed.
            if (entity.ExpiresAtUtc <= now)
            {
                return new RefreshTokenRotationResultDto
                {
                    Status = RefreshTokenRotationStatus.Invalid,
                    UserId = entity.UserId,
                    DeviceId = entity.DeviceId
                };
            }

            var rotated = await RotateCoreAsync(
                entity,
                tokenHash,
                now,
                withinGrace: false,
                cancellationToken);

            if (rotated is not null)
                return rotated;

            // Another request rotated this token first; re-read it and
            // re-evaluate (it may now fall into the grace / theft logic).
        }

        // Repeatedly lost concurrent rotations; give up this request.
        return new RefreshTokenRotationResultDto
        {
            Status = RefreshTokenRotationStatus.Invalid
        };
    }

    public async Task<bool> RevokeByTokenAsync(
        string token,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(token))
            return false;

        var tokenHash = HashToken(token);
        var now = DateTime.UtcNow;

        var revokedRows = await _context.RefreshTokens
            .Where(x =>
                x.TokenHash == tokenHash &&
                x.RevokedAtUtc == null)
            .ExecuteUpdateAsync(
                update => update
                    .SetProperty(x => x.RevokedAtUtc, now),
                cancellationToken);

        return revokedRows > 0;
    }

    public async Task<bool> RevokeAsync(
        string userId,
        string deviceId,
        CancellationToken cancellationToken = default)
    {
        var tokens = await _context.RefreshTokens
            .Where(x =>
                x.UserId == userId &&
                x.DeviceId == deviceId &&
                x.RevokedAtUtc == null)
            .ToListAsync(cancellationToken);

        if (tokens.Count == 0)
            return false;

        var now = DateTime.UtcNow;

        foreach (var token in tokens)
        {
            token.RevokedAtUtc = now;
        }

        await _context.SaveChangesAsync(cancellationToken);

        return true;
    }

    public async Task RevokeAllAsync(
        string userId,
        CancellationToken cancellationToken = default)
    {
        var now = DateTime.UtcNow;

        await _context.RefreshTokens
            .Where(x =>
                x.UserId == userId &&
                x.RevokedAtUtc == null &&
                x.ExpiresAtUtc > now)
            .ExecuteUpdateAsync(
                update => update
                    .SetProperty(x => x.RevokedAtUtc, now),
                cancellationToken);
    }

    /// <summary>
    /// Marks the presented token as replaced and inserts its successor in
    /// one transaction. The conditional update makes rotation atomic: only
    /// one concurrent request can claim the token. Returns null when another
    /// request got there first.
    /// </summary>
    private async Task<RefreshTokenRotationResultDto?> RotateCoreAsync(
        RefreshToken entity,
        string tokenHash,
        DateTime now,
        bool withinGrace,
        CancellationToken cancellationToken)
    {
        var rawToken = GenerateToken();
        var newHash = HashToken(rawToken);
        var expiresAtUtc = now.AddDays(
            _jwtSettings.RefreshTokenExpirationDays);

        await using var transaction =
            await _context.Database.BeginTransactionAsync(cancellationToken);

        // Within the grace window the row is already revoked; only the
        // replacement pointer moves. RevokedAtUtc is deliberately NOT
        // touched, so the grace window cannot be extended by repeated reuse.
        var claimedRows = withinGrace
            ? await _context.RefreshTokens
                .Where(x =>
                    x.TokenHash == tokenHash &&
                    x.ReplacedByTokenHash != null)
                .ExecuteUpdateAsync(
                    update => update
                        .SetProperty(x => x.ReplacedByTokenHash, newHash)
                        .SetProperty(x => x.LastUsedAtUtc, now),
                    cancellationToken)
            : await _context.RefreshTokens
                .Where(x =>
                    x.TokenHash == tokenHash &&
                    x.RevokedAtUtc == null)
                .ExecuteUpdateAsync(
                    update => update
                        .SetProperty(x => x.RevokedAtUtc, now)
                        .SetProperty(x => x.ReplacedByTokenHash, newHash)
                        .SetProperty(x => x.LastUsedAtUtc, now),
                    cancellationToken);

        if (claimedRows == 0)
            return null;

        await _context.RefreshTokens.AddAsync(
            new RefreshToken
            {
                Id = Guid.NewGuid(),
                UserId = entity.UserId,
                DeviceId = entity.DeviceId,
                DeviceName = entity.DeviceName,
                DeviceType = entity.DeviceType,
                TokenHash = newHash,
                CreatedAtUtc = now,
                LastUsedAtUtc = now,
                ExpiresAtUtc = expiresAtUtc
            },
            cancellationToken);

        await _context.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        return new RefreshTokenRotationResultDto
        {
            Status = RefreshTokenRotationStatus.Rotated,
            NewToken = new RefreshTokenResultDto
            {
                Token = rawToken,
                ExpiresAtUtc = expiresAtUtc
            },
            UserId = entity.UserId,
            DeviceId = entity.DeviceId
        };
    }

    private static string GenerateToken()
    {
        return Convert.ToBase64String(
                RandomNumberGenerator.GetBytes(64))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static string HashToken(string token)
    {
        return Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(token)));
    }
}
