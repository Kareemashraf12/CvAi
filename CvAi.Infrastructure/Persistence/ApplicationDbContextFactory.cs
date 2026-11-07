using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace CvAi.Infrastructure.Persistence;

/// <summary>
/// Used ONLY by EF Core tools (dotnet ef migrations / database update).
/// It lets the tools create the DbContext without starting the whole
/// application, so they no longer depend on Program.cs, its settings
/// validation, or on which project is chosen as the startup project.
///
/// Connection string lookup order:
///   1. Environment variable ConnectionStrings__CvAiConnection
///   2. appsettings.{Environment}.json, then appsettings.json
///      (searched from the current folder, its sub-folders and up to 3 parent folders)
///
/// User-secrets are not read here. If the connection string lives in
/// user-secrets, pass it through the environment variable instead.
/// </summary>
public sealed class ApplicationDbContextFactory
    : IDesignTimeDbContextFactory<ApplicationDbContext>
{
    private const string ConnectionName = "CvAiConnection";
    private const string EnvironmentVariableName =
        "ConnectionStrings__CvAiConnection";

    public ApplicationDbContext CreateDbContext(string[] args)
    {
        var connectionString = ResolveConnectionString();

        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseSqlServer(connectionString)
            .Options;

        return new ApplicationDbContext(options);
    }

    private static string ResolveConnectionString()
    {
        var fromEnvironment =
            Environment.GetEnvironmentVariable(EnvironmentVariableName);

        if (!string.IsNullOrWhiteSpace(fromEnvironment))
            return fromEnvironment;

        var environmentName =
            Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ??
            Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT") ??
            "Development";

        var fileNames = new[]
        {
            $"appsettings.{environmentName}.json",
            "appsettings.json"
        };

        foreach (var directory in CandidateDirectories())
        {
            foreach (var fileName in fileNames)
            {
                var path = Path.Combine(directory, fileName);

                if (!File.Exists(path))
                    continue;

                var value = TryReadConnectionString(path);

                if (!string.IsNullOrWhiteSpace(value))
                    return value;
            }
        }

        throw new InvalidOperationException(
            $"Connection string '{ConnectionName}' was not found. " +
            $"Set the environment variable '{EnvironmentVariableName}' " +
            "or run the command from the API project folder " +
            "(the one that contains appsettings.json).");
    }

    private static IEnumerable<string> CandidateDirectories()
    {
        var directory = new DirectoryInfo(Directory.GetCurrentDirectory());

        for (var level = 0; level < 4 && directory is not null; level++)
        {
            yield return directory.FullName;

            foreach (var child in SafeGetDirectories(directory))
                yield return child;

            directory = directory.Parent;
        }
    }

    private static IEnumerable<string> SafeGetDirectories(DirectoryInfo directory)
    {
        try
        {
            return directory
                .GetDirectories()
                .Where(d =>
                    !d.Name.Equals("bin", StringComparison.OrdinalIgnoreCase) &&
                    !d.Name.Equals("obj", StringComparison.OrdinalIgnoreCase) &&
                    !d.Name.StartsWith('.'))
                .Select(d => d.FullName)
                .ToList();
        }
        catch (Exception)
        {
            return Array.Empty<string>();
        }
    }

    private static string? TryReadConnectionString(string path)
    {
        try
        {
            using var document = JsonDocument.Parse(
                File.ReadAllText(path),
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = true,
                    CommentHandling = JsonCommentHandling.Skip
                });

            if (document.RootElement.TryGetProperty(
                    "ConnectionStrings", out var connectionStrings) &&
                connectionStrings.TryGetProperty(
                    ConnectionName, out var value) &&
                value.ValueKind == JsonValueKind.String)
            {
                return value.GetString();
            }
        }
        catch (Exception)
        {
            // Unreadable or invalid JSON: ignore this file and keep looking.
        }

        return null;
    }
}