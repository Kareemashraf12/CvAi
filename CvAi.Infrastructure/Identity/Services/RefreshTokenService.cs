using System.Security.Cryptography;
using System.Text;
using CvAi.Application.Abstractions.Authentication;
using CvAi.Application.Common.Settings;
using CvAi.Application.DTOs.Authentication;
using CvAi.Domain.Entities;
using CvAi.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace CvAi.Infrastructure.Identity.Services;

public sealed class RefreshTokenService : IRefreshTokenService
{
    private readonly ApplicationDbContext _context;
    private readonly JwtSettings _jwtSettings;
    private readonly AuthenticationSettings _authenticationSettings;

    public RefreshTokenService(
        ApplicationDbContext context,
        JwtSettings jwtSettings,
        AuthenticationSettings authenticationSettings)
    {
        _context = context;
        _jwtSettings = jwtSettings;
        _authenticationSettings = authenticationSettings;
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

    public async Task<RefreshTokenValidationDto?> ValidateAsync(
        string token,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(token))
            return null;

        var tokenHash = HashToken(token);
        var now = DateTime.UtcNow;

        var entity = await _context.RefreshTokens
            .FirstOrDefaultAsync(
                x => x.TokenHash == tokenHash &&
                     x.RevokedAtUtc == null &&
                     x.ExpiresAtUtc > now,
                cancellationToken);

        if (entity is null)
            return null;

        entity.LastUsedAtUtc = now;

        await _context.SaveChangesAsync(cancellationToken);

        return new RefreshTokenValidationDto
        {
            UserId = entity.UserId,
            DeviceId = entity.DeviceId,
            ExpiresAtUtc = entity.ExpiresAtUtc
        };
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

        var activeTokens = await _context.RefreshTokens
            .Where(x =>
                x.UserId == userId &&
                x.RevokedAtUtc == null &&
                x.ExpiresAtUtc > now)
            .ToListAsync(cancellationToken);

        foreach (var token in activeTokens)
        {
            token.RevokedAtUtc = now;
        }

        await _context.SaveChangesAsync(cancellationToken);
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