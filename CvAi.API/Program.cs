using CvAi.Application.Common.Settings;
using CvAi.Infrastructure;
using CvAi.Infrastructure.Email.Settings;
using CvAi.Infrastructure.Identity;
using CvAi.Infrastructure.Persistence;
using CvAi.Infrastructure.Storage.Settings;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// ---------------------------------------------------------------
// JWT Settings
// ---------------------------------------------------------------
var jwtSettings = builder.Configuration
    .GetSection(JwtSettings.SectionName)
    .Get<JwtSettings>()
    ?? throw new InvalidOperationException("JWT settings are missing.");

if (string.IsNullOrWhiteSpace(jwtSettings.SecretKey))
    throw new InvalidOperationException("JWT SecretKey is required.");

if (Encoding.UTF8.GetByteCount(jwtSettings.SecretKey) < 32)
    throw new InvalidOperationException("JWT SecretKey must be at least 32 bytes.");

if (string.IsNullOrWhiteSpace(jwtSettings.Issuer) ||
    string.IsNullOrWhiteSpace(jwtSettings.Audience))
{
    throw new InvalidOperationException("JWT Issuer and Audience are required.");
}

if (jwtSettings.AccessTokenExpirationMinutes <= 0 ||
    jwtSettings.RefreshTokenExpirationDays <= 0)
{
    throw new InvalidOperationException("JWT token expiration values must be positive.");
}

builder.Services.AddSingleton(jwtSettings);

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = jwtSettings.Issuer,

            ValidateAudience = true,
            ValidAudience = jwtSettings.Audience,

            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(jwtSettings.SecretKey)),

            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30),

            NameClaimType = System.Security.Claims.ClaimTypes.NameIdentifier,
            RoleClaimType = System.Security.Claims.ClaimTypes.Role
        };
    });

builder.Services.AddAuthorization();

// ---------------------------------------------------------------
// Authentication Settings
// ---------------------------------------------------------------
var authenticationSettings = builder.Configuration
    .GetSection(AuthenticationSettings.SectionName)
    .Get<AuthenticationSettings>()
    ?? throw new InvalidOperationException(
        "Authentication settings are missing.");

if (authenticationSettings.MaxActiveDevices <= 0)
{
    throw new InvalidOperationException(
        "MaxActiveDevices must be greater than zero.");
}

builder.Services.AddSingleton(authenticationSettings);

// ---------------------------------------------------------------
// Database Configuration
// ---------------------------------------------------------------
var connectionString = builder.Configuration
    .GetConnectionString("CvAiConnection");

if (string.IsNullOrWhiteSpace(connectionString))
{
    throw new InvalidOperationException(
        "Connection string 'CvAiConnection' was not found.");
}

builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlServer(connectionString);
});

// ---------------------------------------------------------------
// Identity
// ---------------------------------------------------------------
builder.Services
    .AddIdentityCore<ApplicationUser>(options =>
    {
        options.User.RequireUniqueEmail = true;

        options.Password.RequiredLength = 8;
        options.Password.RequireDigit = false;
        options.Password.RequireLowercase = false;
        options.Password.RequireUppercase = false;
        options.Password.RequireNonAlphanumeric = false;

        options.Lockout.AllowedForNewUsers = true;
        options.Lockout.MaxFailedAccessAttempts = 5;
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    })
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// ---------------------------------------------------------------
// Controllers / Swagger / Error handling
// ---------------------------------------------------------------
builder.Services.AddControllers();
builder.Services.AddProblemDetails();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// ---------------------------------------------------------------
// S3 Storage Configuration
// ---------------------------------------------------------------
var s3Settings = builder.Configuration
    .GetSection(S3StorageSettings.SectionName)
    .Get<S3StorageSettings>() ?? new S3StorageSettings();

var imageSettings = builder.Configuration
    .GetSection(ImageSettings.SectionName)
    .Get<ImageSettings>() ?? new ImageSettings();

builder.Services.AddS3Storage(
    s3Settings,
    imageSettings);

// ---------------------------------------------------------------
// Application services
// ---------------------------------------------------------------
builder.Services.AddIdentitySeeding(builder.Configuration);
builder.Services.AddJwtServices();
builder.Services.AddEmailServices();
builder.Services.AddRegistrationServices();

// ---------------------------------------------------------------
// OTP / Pending Registration Settings
// ---------------------------------------------------------------
var pendingRegistrationSettings = builder.Configuration
    .GetSection(PendingRegistrationSettings.SectionName)
    .Get<PendingRegistrationSettings>()
    ?? throw new InvalidOperationException(
        "PendingRegistration settings are missing.");

if (string.IsNullOrWhiteSpace(pendingRegistrationSettings.OtpHashSecret))
{
    throw new InvalidOperationException(
        "OTP hash secret is required.");
}

try
{
    var secret = Convert.FromBase64String(
        pendingRegistrationSettings.OtpHashSecret);

    if (secret.Length < 32)
    {
        throw new InvalidOperationException(
            "OTP hash secret must contain at least 32 bytes.");
    }
}
catch (FormatException)
{
    throw new InvalidOperationException(
        "OTP hash secret must be valid Base64.");
}

if (pendingRegistrationSettings.RegistrationExpirationHours <= 0 ||
    pendingRegistrationSettings.OtpLength < 4 ||
    pendingRegistrationSettings.OtpLength > 8 ||
    pendingRegistrationSettings.OtpExpirationMinutes <= 0 ||
    pendingRegistrationSettings.OtpResendCooldownSeconds < 0 ||
    pendingRegistrationSettings.MaxOtpAttempts <= 0 ||
    pendingRegistrationSettings.MaxOtpResendCount < 0)
{
    throw new InvalidOperationException(
        "PendingRegistration settings are invalid.");
}

builder.Services.AddSingleton(pendingRegistrationSettings);

// ---------------------------------------------------------------
// Email Settings
// ---------------------------------------------------------------
builder.Services
    .AddOptions<EmailSettings>()
    .Bind(builder.Configuration.GetSection(EmailSettings.SectionName))
    .Validate(
        settings =>
            !string.IsNullOrWhiteSpace(settings.Host) &&
            settings.Port > 0 &&
            !string.IsNullOrWhiteSpace(settings.Username) &&
            !string.IsNullOrWhiteSpace(settings.Password) &&
            !string.IsNullOrWhiteSpace(settings.FromEmail),
        "Email settings are invalid.")
    .ValidateOnStart();

var app = builder.Build();

// ---------------------------------------------------------------
// Seed identity data
// ---------------------------------------------------------------
using (var scope = app.Services.CreateScope())
{
    var seeder = scope.ServiceProvider
        .GetRequiredService<IdentitySeeder>();

    await seeder.SeedAsync();
}

// ---------------------------------------------------------------
// HTTP Request Pipeline
// ---------------------------------------------------------------

    app.UseSwagger();
    app.UseSwaggerUI();


app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();