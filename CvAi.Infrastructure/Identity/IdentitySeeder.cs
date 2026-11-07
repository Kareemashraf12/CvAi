using CvAi.Infrastructure.Identity.Settings;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace CvAi.Infrastructure.Identity;

public sealed class IdentitySeeder
{
    private const string AdminRole = "Admin";
    private const string UserRole = "User";

    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly AdminSeedSettings _settings;

    public IdentitySeeder(
        UserManager<ApplicationUser> userManager,
        RoleManager<IdentityRole> roleManager,
        IOptions<AdminSeedSettings> options)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _settings = options.Value;
    }

    public async Task SeedAsync()
    {
        ValidateSettings();

        await EnsureRoleAsync(AdminRole);
        await EnsureRoleAsync(UserRole);

        var admin = await _userManager.FindByEmailAsync(
            _settings.Email);

        if (admin is null)
        {
            admin = new ApplicationUser
            {
                UserName = _settings.Email,
                Email = _settings.Email,
                FullName = _settings.FullName,
                EmailConfirmed = true
            };

            var createResult = await _userManager.CreateAsync(
                admin,
                _settings.Password);

            if (!createResult.Succeeded)
            {
                throw new InvalidOperationException(
                    "Failed to create the initial admin: " +
                    string.Join(", ",
                        createResult.Errors.Select(e => e.Description)));
            }
        }
        else
        {
            var hasChanges = false;

            if (string.IsNullOrWhiteSpace(admin.FullName))
            {
                admin.FullName = _settings.FullName;
                hasChanges = true;
            }

            if (!admin.EmailConfirmed)
            {
                admin.EmailConfirmed = true;
                hasChanges = true;
            }

            if (hasChanges)
            {
                var updateResult =
                    await _userManager.UpdateAsync(admin);

                if (!updateResult.Succeeded)
                {
                    throw new InvalidOperationException(
                        "Failed to update the initial admin: " +
                        string.Join(", ",
                            updateResult.Errors.Select(e => e.Description)));
                }
            }
        }

        if (!await _userManager.IsInRoleAsync(admin, AdminRole))
        {
            var roleResult = await _userManager.AddToRoleAsync(
                admin,
                AdminRole);

            if (!roleResult.Succeeded)
            {
                throw new InvalidOperationException(
                    "Failed to assign Admin role: " +
                    string.Join(", ",
                        roleResult.Errors.Select(e => e.Description)));
            }
        }
    }

    private async Task EnsureRoleAsync(string roleName)
    {
        if (await _roleManager.RoleExistsAsync(roleName))
            return;

        var result = await _roleManager.CreateAsync(
            new IdentityRole(roleName));

        if (!result.Succeeded)
        {
            throw new InvalidOperationException(
                $"Failed to create role '{roleName}': " +
                string.Join(", ",
                    result.Errors.Select(e => e.Description)));
        }
    }

    private void ValidateSettings()
    {
        if (string.IsNullOrWhiteSpace(_settings.FullName))
            throw new InvalidOperationException(
                "AdminSeed:FullName is required.");

        if (string.IsNullOrWhiteSpace(_settings.Email))
            throw new InvalidOperationException(
                "AdminSeed:Email is required.");

        if (string.IsNullOrWhiteSpace(_settings.Password))
            throw new InvalidOperationException(
                "AdminSeed:Password is required.");
    }
}