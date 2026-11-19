namespace CvAi.Application.DTOs.Authentication;

public sealed class ResetPasswordRequestDto
{
    public string Email { get; init; } = string.Empty;

    public string Code { get; init; } = string.Empty;

    public string NewPassword { get; init; } = string.Empty;

    public string ConfirmPassword { get; init; } = string.Empty;
}
