using Amazon.S3;
using Amazon.S3.Model;
using CvAi.Application.Abstractions.Files;
using CvAi.Application.Common.Settings;
using CvAi.Infrastructure.Storage.Settings;

namespace CvAi.Infrastructure.Storage.Services;

public sealed class ImageService : IImageService
{
    private const string ImagesFolder = "profile-images/";
    private const int SignedUrlExpirationMinutes = 10;

    private readonly IAmazonS3 _s3Client;
    private readonly S3StorageSettings _s3Settings;
    private readonly ImageSettings _imageSettings;

    public ImageService(
        IAmazonS3 s3Client,
        S3StorageSettings s3Settings,
        ImageSettings imageSettings)
    {
        _s3Client = s3Client;
        _s3Settings = s3Settings;
        _imageSettings = imageSettings;
    }

    public async Task<string> UploadAsync(
        Stream fileStream,
        string fileName,
        string contentType,
        long fileSize,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(fileStream);

        if (!fileStream.CanRead)
            throw new InvalidDataException("The uploaded file cannot be read.");

        if (fileSize <= 0 ||
            fileSize > _imageSettings.MaxFileSizeInBytes)
        {
            throw new InvalidDataException("Invalid image file size.");
        }

        var extension = Path.GetExtension(fileName)
            .ToLowerInvariant();

        if (!_imageSettings.AllowedExtensions.Contains(
                extension,
                StringComparer.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "This image extension is not allowed.");
        }

        await using var memoryStream = new MemoryStream();

        var buffer = new byte[81920];

        int bytesRead;

        while ((bytesRead = await fileStream.ReadAsync(
                   buffer.AsMemory(0, buffer.Length),
                   cancellationToken)) > 0)
        {
            if (memoryStream.Length + bytesRead >
                _imageSettings.MaxFileSizeInBytes)
            {
                throw new InvalidDataException(
                    "The uploaded image exceeds the maximum allowed size.");
            }

            await memoryStream.WriteAsync(
                buffer.AsMemory(0, bytesRead),
                cancellationToken);
        }

        if (memoryStream.Length != fileSize)
        {
            throw new InvalidDataException(
                "The uploaded file size does not match the supplied file size.");
        }

        var fileBytes = memoryStream.ToArray();

        var detectedType = DetectImageType(fileBytes);

        if (detectedType.Extension != extension)
        {
            throw new InvalidDataException(
                "The file content does not match its extension.");
        }

        if (!string.Equals(
                detectedType.ContentType,
                contentType,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "The file content does not match its content type.");
        }

        if (!_imageSettings.AllowedContentTypes.Contains(
                detectedType.ContentType,
                StringComparer.OrdinalIgnoreCase))
        {
            throw new InvalidDataException(
                "This image content type is not allowed.");
        }

        var imageKey =
            $"{ImagesFolder}{Guid.NewGuid():N}{detectedType.Extension}";

        memoryStream.Position = 0;

        var request = new PutObjectRequest
        {
            BucketName = _s3Settings.BucketName,
            Key = imageKey,
            InputStream = memoryStream,
            ContentType = detectedType.ContentType
        };

        await _s3Client.PutObjectAsync(
            request,
            cancellationToken);

        return imageKey;
    }

    public async Task DeleteAsync(
        string imageKey,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(imageKey))
            return;

        // Only allow deletion of objects managed by this service.
        if (!imageKey.StartsWith(
                ImagesFolder,
                StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "Invalid profile image key.",
                nameof(imageKey));
        }

        await _s3Client.DeleteObjectAsync(
            _s3Settings.BucketName,
            imageKey,
            cancellationToken);
    }

    public async Task<string> GetImageUrlAsync(
        string? imageKey,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(imageKey))
            return _imageSettings.DefaultAvatarUrl;

        if (!imageKey.StartsWith(
                ImagesFolder,
                StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "Invalid profile image key.",
                nameof(imageKey));
        }

        if (_s3Settings.UsePublicUrls)
        {
            if (string.IsNullOrWhiteSpace(_s3Settings.PublicBaseUrl))
            {
                throw new InvalidOperationException(
                    "S3 PublicBaseUrl is not configured.");
            }

            var escapedKey = string.Join(
                "/",
                imageKey.Split('/')
                    .Select(Uri.EscapeDataString));

            return $"{_s3Settings.PublicBaseUrl.TrimEnd('/')}/{escapedKey}";
        }

        var request = new GetPreSignedUrlRequest
        {
            BucketName = _s3Settings.BucketName,
            Key = imageKey,
            Verb = HttpVerb.GET,
            Expires = DateTime.UtcNow.AddMinutes(
                SignedUrlExpirationMinutes)
        };

        return await _s3Client.GetPreSignedURLAsync(request);
    }

    private static (string Extension, string ContentType)
        DetectImageType(byte[] bytes)
    {
        // JPEG signature
        if (bytes.Length >= 3 &&
            bytes[0] == 0xFF &&
            bytes[1] == 0xD8 &&
            bytes[2] == 0xFF)
        {
            return (".jpg", "image/jpeg");
        }

        // PNG signature
        if (bytes.Length >= 8 &&
            bytes[0] == 0x89 &&
            bytes[1] == 0x50 &&
            bytes[2] == 0x4E &&
            bytes[3] == 0x47 &&
            bytes[4] == 0x0D &&
            bytes[5] == 0x0A &&
            bytes[6] == 0x1A &&
            bytes[7] == 0x0A)
        {
            return (".png", "image/png");
        }

        // WebP signature
        if (bytes.Length >= 12 &&
            bytes[0] == (byte)'R' &&
            bytes[1] == (byte)'I' &&
            bytes[2] == (byte)'F' &&
            bytes[3] == (byte)'F' &&
            bytes[8] == (byte)'W' &&
            bytes[9] == (byte)'E' &&
            bytes[10] == (byte)'B' &&
            bytes[11] == (byte)'P')
        {
            return (".webp", "image/webp");
        }

        throw new InvalidDataException(
            "The uploaded file is not a supported image.");
    }
}