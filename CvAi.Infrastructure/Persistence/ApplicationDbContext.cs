using CvAi.Domain.Entities;
using CvAi.Infrastructure.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace CvAi.Infrastructure.Persistence;

public sealed class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{
    public ApplicationDbContext(
        DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();
    public DbSet<PendingRegistration> PendingRegistrations
    => Set<PendingRegistration>();
    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<RefreshToken>(entity =>
        {
            entity.HasKey(x => x.Id);

            entity.Property(x => x.UserId)
                .HasMaxLength(450)
                .IsRequired();

            entity.Property(x => x.TokenHash)
                .HasMaxLength(128)
                .IsRequired();

            entity.Property(x => x.DeviceId)
                .HasMaxLength(200)
                .IsRequired();

            entity.Property(x => x.DeviceName)
                .HasMaxLength(100);

            entity.Property(x => x.DeviceType)
                .HasMaxLength(50);

            entity.HasIndex(x => new { x.UserId, x.DeviceId });

            entity.HasIndex(x => x.TokenHash).IsUnique();
            entity.HasIndex(x => x.UserId);
        });

        builder.Entity<PendingRegistration>(entity =>
        {
            entity.HasKey(x => x.Id);

            entity.Property(x => x.FullName)
                .HasMaxLength(150)
                .IsRequired();

            entity.Property(x => x.Email)
                .HasMaxLength(256)
                .IsRequired();

            entity.Property(x => x.NormalizedEmail)
                .HasMaxLength(256)
                .IsRequired();

            entity.Property(x => x.PasswordHash)
                .HasMaxLength(500)
                .IsRequired();

            entity.Property(x => x.OtpHash)
                .HasMaxLength(128)
                .IsRequired();

            entity.HasIndex(x => x.NormalizedEmail)
                .IsUnique();

            entity.HasIndex(x => x.ExpiresAtUtc);
        });
    }
}