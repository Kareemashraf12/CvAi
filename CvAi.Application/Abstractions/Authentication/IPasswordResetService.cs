using CvAi.Application.Common.Models;
using CvAi.Application.DTOs.Authentication;

namespace CvAi.Application.Abstractions.Authentication;

public interface IPasswordResetService
{
    /// <summary>
    /// Sends a password reset code to the given email. The response is
    /// always generic: it never reveals whether the account exists.
    /// </summary>
    Task<ApiResponse> RequestResetAsync(
        ForgotPasswordRequestDto request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies the reset code and changes the password. Revokes every
    /// active session of the user on success.
    /// </summary>
    Task<ApiResponse> ResetPasswordAsync(
        ResetPasswordRequestDto request,
        CancellationToken cancellationToken = default);
}
