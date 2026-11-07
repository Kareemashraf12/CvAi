namespace CvAi.Application.Common.Models;

public class ApiResponse
{
    public bool Success { get; init; }

    public string Message { get; init; } = string.Empty;

    public IReadOnlyDictionary<string, string[]>? Errors { get; init; }

    public static ApiResponse Ok(
        string message = "Operation completed successfully.")
    {
        return new ApiResponse
        {
            Success = true,
            Message = message
        };
    }

    public static ApiResponse Fail(
        string message,
        IReadOnlyDictionary<string, string[]>? errors = null)
    {
        return new ApiResponse
        {
            Success = false,
            Message = message,
            Errors = errors
        };
    }
}