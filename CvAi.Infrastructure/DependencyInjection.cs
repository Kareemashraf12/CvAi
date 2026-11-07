using Amazon.S3;
using CvAi.Application.Abstractions.Authentication;
using CvAi.Application.Abstractions.Email;
using CvAi.Application.Abstractions.Files;
using CvAi.Application.Common.Settings;
using CvAi.Infrastructure.Email.Services;
using CvAi.Infrastructure.Identity;
using CvAi.Infrastructure.Identity.Services;
using CvAi.Infrastructure.Identity.Settings;
using CvAi.Infrastructure.Storage;
using CvAi.Infrastructure.Storage.Services;
using CvAi.Infrastructure.Storage.Settings;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace CvAi.Infrastructure;

public static class DependencyInjection
{
    /// <summary>
    /// Storage: S3 client and image handling.
    /// </summary>
    public static IServiceCollection AddS3Storage(
        this IServiceCollection services,
        S3StorageSettings s3Settings,
        ImageSettings imageSettings)
    {
        services.AddSingleton(s3Settings);
        services.AddSingleton(imageSettings);

        services.AddSingleton<IAmazonS3>(_ =>
            S3ClientFactory.Create(s3Settings));

        services.AddScoped<IImageService, ImageService>();

        return services;
    }

    /// <summary>
    /// Email sending.
    /// </summary>
    public static IServiceCollection AddEmailServices(
        this IServiceCollection services)
    {
        services.AddScoped<IEmailService, EmailService>();

        return services;
    }

    /// <summary>
    /// Registration flow: OTP generation/verification and pending registrations.
    /// </summary>
    public static IServiceCollection AddRegistrationServices(
        this IServiceCollection services)
    {
        services.AddScoped<IOtpService, OtpService>();
        services.AddScoped<IPendingRegistrationService, PendingRegistrationService>();

        return services;
    }

    /// <summary>
    /// Identity seeding (admin user and roles).
    /// </summary>
    public static IServiceCollection AddIdentitySeeding(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.Configure<AdminSeedSettings>(
            configuration.GetSection(AdminSeedSettings.SectionName));

        services.AddScoped<IdentitySeeder>();

        return services;
    }

    /// <summary>
    /// Authentication: login/refresh service, JWT access tokens and refresh tokens.
    /// </summary>
    public static IServiceCollection AddJwtServices(
        this IServiceCollection services)
    {
        services.AddScoped<IAuthenticationService, AuthenticationService>();
        services.AddScoped<IJwtTokenService, JwtTokenService>();
        services.AddScoped<IRefreshTokenService, RefreshTokenService>();

        return services;
    }
}