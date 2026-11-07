namespace CvAi.Application.Common.Settings;

public sealed class AuthenticationSettings
{
    public const string SectionName = "Authentication";

    public int MaxActiveDevices { get; set; } = 5;
}