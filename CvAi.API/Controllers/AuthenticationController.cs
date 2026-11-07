using CvAi.Application.Abstractions.Authentication;
using CvAi.Application.DTOs.Authentication;
using Microsoft.AspNetCore.Mvc;

namespace CvAi.API.Controllers;

[ApiController]
[Route("api/auth")]
public sealed class AuthenticationController : ControllerBase
{
    private readonly IAuthenticationService _authenticationService;

    public AuthenticationController(
        IAuthenticationService authenticationService)
    {
        _authenticationService = authenticationService;
    }

    /// <summary>
    /// Register a new user and send an email verification OTP.
    /// </summary>
    [HttpPost("register")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Register(
        [FromBody] RegisterRequestDto request,
        CancellationToken cancellationToken)
    {
        var result = await _authenticationService.RegisterAsync(
            request,
            cancellationToken);

        return result.Success
            ? Ok(result)
            : BadRequest(result);
    }

    /// <summary>
    /// Login using email and password.
    /// </summary>
    [HttpPost("login")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Login(
        [FromBody] LoginRequestDto request,
        CancellationToken cancellationToken)
    {
        var result = await _authenticationService.LoginAsync(
            request,
            cancellationToken);

        return result.Success
            ? Ok(result)
            : Unauthorized(result);
    }

    /// <summary>
    /// Generate a new access token using an existing refresh token.
    /// </summary>
    [HttpPost("refresh-token")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> RefreshToken(
        [FromBody] RefreshTokenRequestDto request,
        CancellationToken cancellationToken)
    {
        var result = await _authenticationService.RefreshAccessTokenAsync(
            request,
            cancellationToken);

        return result.Success
            ? Ok(result)
            : Unauthorized(result);
    }

    /// <summary>
    /// Send an OTP to the email associated with a pending registration.
    /// </summary>
    [HttpPost("send-otp")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> SendOtp(
        [FromBody] SendOtpRequestDto request,
        CancellationToken cancellationToken)
    {
        var result = await _authenticationService.SendOtpAsync(
            request,
            cancellationToken);

        return result.Success
            ? Ok(result)
            : BadRequest(result);
    }

    /// <summary>
    /// Resend the email verification OTP.
    /// </summary>
    [HttpPost("resend-otp")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> ResendOtp(
        [FromBody] ResendEmailOtpRequestDto request,
        CancellationToken cancellationToken)
    {
        var result = await _authenticationService.ResendOtpAsync(
            request,
            cancellationToken);

        return result.Success
            ? Ok(result)
            : BadRequest(result);
    }

    /// <summary>
    /// Verify email using the OTP sent to the user's email.
    /// </summary>
    [HttpPost("verify-email")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> VerifyEmail(
        [FromBody] VerifyEmailOtpRequestDto request,
        CancellationToken cancellationToken)
    {
        var result = await _authenticationService.VerifyEmailAsync(
            request,
            cancellationToken);

        return result.Success
            ? Ok(result)
            : BadRequest(result);
    }
}