using CvAi.Application.Abstractions.Email;
using CvAi.Infrastructure.Email.Settings;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Options;
using MimeKit;

namespace CvAi.Infrastructure.Email.Services;

public sealed class EmailService : IEmailService
{
    private readonly EmailSettings _settings;

    public EmailService(IOptions<EmailSettings> options)
    {
        _settings = options.Value;
    }

    public async Task SendEmailAsync(
        string to,
        string subject,
        string body,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(to))
            throw new ArgumentException("Recipient email is required.");

        var message = new MimeMessage();

        message.From.Add(
            new MailboxAddress(_settings.FromName, _settings.FromEmail));

        message.To.Add(MailboxAddress.Parse(to));

        message.Subject = subject;

        message.Body = new TextPart("plain")
        {
            Text = body
        };

        using var smtpClient = new SmtpClient();

        var securityOption = !_settings.EnableSsl
            ? SecureSocketOptions.None
            : _settings.Port == 465
                ? SecureSocketOptions.SslOnConnect
                : SecureSocketOptions.StartTls;

        await smtpClient.ConnectAsync(
            _settings.Host,
            _settings.Port,
            securityOption,
            cancellationToken);

        await smtpClient.AuthenticateAsync(
            _settings.Username,
            _settings.Password,
            cancellationToken);

        await smtpClient.SendAsync(message, cancellationToken);

        await smtpClient.DisconnectAsync(
            true,
            cancellationToken);
    }
}