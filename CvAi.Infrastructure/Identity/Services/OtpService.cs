using System.Security.Cryptography;
using System.Text;
using CvAi.Application.Abstractions.Authentication;
using CvAi.Application.Common.Settings;

namespace CvAi.Infrastructure.Identity.Services;

public sealed class OtpService : IOtpService
{
    private const int MinOtpLength = 4;
    private const int MaxOtpLength = 8;

    private readonly byte[] _secretKey;
    private readonly int _otpLength;
    private readonly int _otpUpperBound;

    public OtpService(PendingRegistrationSettings settings)
    {
        if (string.IsNullOrWhiteSpace(settings.OtpHashSecret))
        {
            throw new InvalidOperationException(
                "OTP hash secret is missing.");
        }

        try
        {
            _secretKey = Convert.FromBase64String(settings.OtpHashSecret);
        }
        catch (FormatException)
        {
            throw new InvalidOperationException(
                "OTP hash secret must be a valid Base64 value.");
        }

        if (_secretKey.Length < 32)
        {
            throw new InvalidOperationException(
                "OTP hash secret must contain at least 32 bytes.");
        }

        if (settings.OtpLength < MinOtpLength ||
            settings.OtpLength > MaxOtpLength)
        {
            throw new InvalidOperationException(
                $"OTP length must be between {MinOtpLength} and {MaxOtpLength}.");
        }

        _otpLength = settings.OtpLength;

        // 10^length computed with integers (no floating-point).
        var upperBound = 1;
        for (var i = 0; i < _otpLength; i++)
        {
            upperBound *= 10;
        }

        _otpUpperBound = upperBound;
    }

    public string GenerateOtp()
    {
        var otp = RandomNumberGenerator.GetInt32(0, _otpUpperBound);

        return otp.ToString($"D{_otpLength}");
    }

    public string HashOtp(string otp)
    {
        using var hmac = new HMACSHA256(_secretKey);

        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(otp));

        return Convert.ToHexString(hash);
    }

    public bool VerifyOtp(string otp, string otpHash)
    {
        if (string.IsNullOrWhiteSpace(otp) ||
            string.IsNullOrWhiteSpace(otpHash))
        {
            return false;
        }

        try
        {
            var expectedHash = Convert.FromHexString(otpHash);
            var suppliedHash = Convert.FromHexString(HashOtp(otp));

            return CryptographicOperations.FixedTimeEquals(
                expectedHash,
                suppliedHash);
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
