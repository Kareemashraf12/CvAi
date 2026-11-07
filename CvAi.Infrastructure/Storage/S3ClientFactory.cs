using Amazon;
using Amazon.Runtime;
using Amazon.S3;
using CvAi.Infrastructure.Storage.Settings;

namespace CvAi.Infrastructure.Storage;

public static class S3ClientFactory
{
    public static IAmazonS3 Create(S3StorageSettings settings)
    {
        var config = new AmazonS3Config
        {
            ForcePathStyle = settings.ForcePathStyle
        };

        if (!string.IsNullOrWhiteSpace(settings.ServiceUrl))
        {
            config.ServiceURL = settings.ServiceUrl;
            config.AuthenticationRegion = settings.Region;
        }
        else
        {
            config.RegionEndpoint =
                RegionEndpoint.GetBySystemName(settings.Region);
        }

        var hasAccessKey =
            !string.IsNullOrWhiteSpace(settings.AccessKey);

        var hasSecretKey =
            !string.IsNullOrWhiteSpace(settings.SecretKey);

        if (hasAccessKey != hasSecretKey)
        {
            throw new InvalidOperationException(
                "Both S3 AccessKey and SecretKey must be configured.");
        }

        if (hasAccessKey)
        {
            var credentials = new BasicAWSCredentials(
                settings.AccessKey,
                settings.SecretKey);

            return new AmazonS3Client(credentials, config);
        }

        // Uses the AWS SDK default credential resolution chain.
        return new AmazonS3Client(config);
    }
}