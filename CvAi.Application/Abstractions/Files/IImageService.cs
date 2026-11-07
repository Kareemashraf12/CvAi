namespace CvAi.Application.Abstractions.Files;

public interface IImageService
{
    Task<string> UploadAsync(
        Stream fileStream,
        string fileName,
        string contentType,
        long fileSize,
        CancellationToken cancellationToken = default);

    Task DeleteAsync(
        string imageKey,
        CancellationToken cancellationToken = default);

    Task<string> GetImageUrlAsync(
        string? imageKey,
        CancellationToken cancellationToken = default);
}