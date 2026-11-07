
using Microsoft.AspNetCore.Identity;

namespace CvAi.Infrastructure.Identity;

public sealed class ApplicationUser : IdentityUser
{
    public string FullName { get; set; } = string.Empty;

    public string? ProfileImageKey { get; set; }
}
