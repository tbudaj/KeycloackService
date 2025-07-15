using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace KeyCloackService.MassTransit;

/// <summary>
/// Credentials provider for MassTransit that uses Keycloak JWT tokens for RabbitMQ authentication
/// </summary>
public class KeycloakCredentialsProvider
{
    private readonly KeycloakTokenManager _tokenManager;
    private readonly ILogger<KeycloakCredentialsProvider>? _logger;

    public KeycloakCredentialsProvider(
        KeycloakTokenManager tokenManager, 
        ILogger<KeycloakCredentialsProvider>? logger = null)
    {
        _tokenManager = tokenManager ?? throw new ArgumentNullException(nameof(tokenManager));
        _logger = logger;
    }

    /// <summary>
    /// Gets RabbitMQ credentials using Keycloak JWT token
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Network credentials with JWT token</returns>
    public async Task<NetworkCredential> GetCredentialsAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            // Get current access token from Keycloak
            var accessToken = await _tokenManager.GetAccessTokenAsync(cancellationToken);
            
            // Parse token to extract username (subject)
            var tokenData = ParseJwtToken(accessToken);
            var username = tokenData?.GetValueOrDefault("sub")?.ToString() 
                ?? tokenData?.GetValueOrDefault("preferred_username")?.ToString()
                ?? "keycloak-user";

            _logger?.LogDebug("Using Keycloak JWT for RabbitMQ authentication with user: {Username}", username);

            // Return credentials with JWT token as password
            // This requires RabbitMQ to be configured with JWT authentication plugin
            return new NetworkCredential(username, accessToken);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to get Keycloak credentials for RabbitMQ");
            throw new InvalidOperationException("Failed to authenticate with Keycloak for RabbitMQ connection", ex);
        }
    }

    /// <summary>
    /// Gets RabbitMQ credentials synchronously (for compatibility with some MassTransit configurations)
    /// Note: This method blocks and should be avoided in async contexts
    /// </summary>
    /// <returns>Network credentials with JWT token</returns>
    public NetworkCredential GetCredentials()
    {
        try
        {
            return GetCredentialsAsync().GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to get Keycloak credentials for RabbitMQ (sync)");
            throw new InvalidOperationException("Failed to authenticate with Keycloak for RabbitMQ connection", ex);
        }
    }

    private Dictionary<string, object>? ParseJwtToken(string token)
    {
        try
        {
            // Simple JWT parsing - split by dots and decode base64 payload
            var parts = token.Split('.');
            if (parts.Length != 3) return null;

            var payload = parts[1];
            
            // Add padding if needed
            var paddingNeeded = 4 - (payload.Length % 4);
            if (paddingNeeded != 4)
            {
                payload += new string('=', paddingNeeded);
            }

            var jsonBytes = Convert.FromBase64String(payload);
            var jsonString = System.Text.Encoding.UTF8.GetString(jsonBytes);
            
            return JsonSerializer.Deserialize<Dictionary<string, object>>(jsonString);
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Failed to parse JWT token");
            return null;
        }
    }
}