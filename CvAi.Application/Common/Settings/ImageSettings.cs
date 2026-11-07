namespace CvAi.Application.Common.Settings;

public sealed class ImageSettings
{
    public const string SectionName = "ImageSettings";

    public long MaxFileSizeInBytes { get; set; } = 5 * 1024 * 1024;

    public string[] AllowedExtensions { get; set; } =
    [
        ".jpg",
        ".jpeg",
        ".png",
        ".webp"
    ];

    public string[] AllowedContentTypes { get; set; } =
    [
        "image/jpeg",
        "image/png",
        "image/webp"
    ];

    public string DefaultAvatarUrl { get; set; } =
        "/images/default-avatar.jpg";
}