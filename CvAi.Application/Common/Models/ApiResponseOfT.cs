namespace CvAi.Application.Common.Models;

public sealed class ApiResponse<T> : ApiResponse
{
    public T? Data { get; init; }

    public static ApiResponse<T> Ok(
        T data,
        string message = "Operation completed successfully.")
    {
        return new ApiResponse<T>
        {
            Success = true,
            Message = message,
            Data = data
        };
    }

    public new static ApiResponse<T> Fail(
        string message,
        IReadOnlyDictionary<string, string[]>? errors = null)
    {
        return new ApiResponse<T>
        {
            Success = false,
            Message = message,
            Errors = errors,
            Data = default
        };
    }
}