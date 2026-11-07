namespace CvAi.Infrastructure.Storage.Settings;

public sealed class S3StorageSettings
{
    public const string SectionName = "S3Storage";

    public string ServiceUrl { get; set; } = string.Empty;

    public string Region { get; set; } = "us-east-1";

    public string BucketName { get; set; } = string.Empty;

    public string AccessKey { get; set; } = string.Empty;

    public string SecretKey { get; set; } = string.Empty;

    public bool ForcePathStyle { get; set; }

    public bool UsePublicUrls { get; set; }

    public string? PublicBaseUrl { get; set; }
}