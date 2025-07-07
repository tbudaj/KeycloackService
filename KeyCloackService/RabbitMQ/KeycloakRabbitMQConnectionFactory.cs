using RabbitMQ.Client;
using RabbitMQ.Client.Exceptions;
using KeyCloackService.Models;
using Microsoft.Extensions.Logging;
using System.Text.Json;

namespace KeyCloackService.RabbitMQ;

/// <summary>
/// Factory for creating RabbitMQ connections with Keycloak token authentication
/// </summary>
public class KeycloakRabbitMQConnectionFactory : IDisposable
{
    private readonly RabbitMQConfig _rabbitConfig;
    private readonly KeycloakTokenManager _tokenManager;
    private readonly ILogger<KeycloakRabbitMQConnectionFactory>? _logger;
    private readonly SemaphoreSlim _connectionSemaphore = new(1, 1);
    
    private IConnection? _connection;
    private bool _disposed = false;

    public KeycloakRabbitMQConnectionFactory(
        RabbitMQConfig rabbitConfig, 
        KeycloakTokenManager tokenManager,
        ILogger<KeycloakRabbitMQConnectionFactory>? logger = null)
    {
        _rabbitConfig = rabbitConfig ?? throw new ArgumentNullException(nameof(rabbitConfig));
        _tokenManager = tokenManager ?? throw new ArgumentNullException(nameof(tokenManager));
        _logger = logger;

        // Subscribe to token refresh events to update RabbitMQ credentials
        _tokenManager.TokenRefreshed += OnTokenRefreshed;
    }

    /// <summary>
    /// Creates a new RabbitMQ connection with Keycloak authentication
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Authenticated RabbitMQ connection</returns>
    public async Task<IConnection> CreateConnectionAsync(CancellationToken cancellationToken = default)
    {
        await _connectionSemaphore.WaitAsync(cancellationToken);
        try
        {
            if (_connection?.IsOpen == true)
            {
                return _connection;
            }

            _connection?.Dispose();
            _connection = await CreateNewConnectionAsync(cancellationToken);
            
            _logger?.LogInformation("RabbitMQ connection established successfully");
            return _connection;
        }
        finally
        {
            _connectionSemaphore.Release();
        }
    }

    /// <summary>
    /// Creates a new RabbitMQ channel from the current connection
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>RabbitMQ channel</returns>
    public async Task<IModel> CreateChannelAsync(CancellationToken cancellationToken = default)
    {
        var connection = await CreateConnectionAsync(cancellationToken);
        return connection.CreateModel();
    }

    private async Task<IConnection> CreateNewConnectionAsync(CancellationToken cancellationToken)
    {
        var factory = new ConnectionFactory
        {
            HostName = _rabbitConfig.HostName,
            Port = _rabbitConfig.Port,
            VirtualHost = _rabbitConfig.VirtualHost,
            RequestedConnectionTimeout = _rabbitConfig.RequestedConnectionTimeout,
            SocketReadTimeout = _rabbitConfig.SocketReadTimeout,
            SocketWriteTimeout = _rabbitConfig.SocketWriteTimeout,
            AutomaticRecoveryEnabled = _rabbitConfig.AutomaticRecoveryEnabled,
            NetworkRecoveryInterval = _rabbitConfig.NetworkRecoveryInterval
        };

        // Configure SSL if enabled
        if (_rabbitConfig.UseSsl)
        {
            factory.Ssl = new SslOption
            {
                Enabled = true,
                ServerName = _rabbitConfig.SslServerName ?? _rabbitConfig.HostName
            };
        }

        // Configure authentication
        if (_rabbitConfig.UseKeycloakAuthentication)
        {
            await ConfigureKeycloakAuthenticationAsync(factory, cancellationToken);
        }
        else
        {
            ConfigureBasicAuthentication(factory);
        }

        try
        {
            return factory.CreateConnection($"KeycloakService-{Environment.MachineName}");
        }
        catch (BrokerUnreachableException ex)
        {
            _logger?.LogError(ex, "Failed to connect to RabbitMQ broker at {HostName}:{Port}", 
                _rabbitConfig.HostName, _rabbitConfig.Port);
            throw new InvalidOperationException($"Unable to connect to RabbitMQ broker at {_rabbitConfig.HostName}:{_rabbitConfig.Port}", ex);
        }
        catch (AuthenticationFailureException ex)
        {
            _logger?.LogError(ex, "RabbitMQ authentication failed");
            throw new UnauthorizedAccessException("RabbitMQ authentication failed. Please check your Keycloak configuration.", ex);
        }
    }

    private async Task ConfigureKeycloakAuthenticationAsync(ConnectionFactory factory, CancellationToken cancellationToken)
    {
        try
        {
            // Get access token from Keycloak
            var accessToken = await _tokenManager.GetAccessTokenAsync(cancellationToken);
            
            // Parse token to extract username (subject)
            var tokenData = ParseJwtToken(accessToken);
            var username = tokenData?.GetValueOrDefault("sub")?.ToString() 
                ?? tokenData?.GetValueOrDefault("preferred_username")?.ToString()
                ?? "keycloak-user";

            // Use the access token as password for RabbitMQ
            // This requires RabbitMQ to be configured with JWT authentication plugin
            factory.UserName = username;
            factory.Password = accessToken;

            _logger?.LogDebug("Configured RabbitMQ authentication with Keycloak token for user: {Username}", username);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to configure Keycloak authentication for RabbitMQ");
            throw new InvalidOperationException("Failed to authenticate with Keycloak for RabbitMQ connection", ex);
        }
    }

    private void ConfigureBasicAuthentication(ConnectionFactory factory)
    {
        if (string.IsNullOrEmpty(_rabbitConfig.Username) || string.IsNullOrEmpty(_rabbitConfig.Password))
        {
            throw new InvalidOperationException("Username and Password are required when UseKeycloakAuthentication is false");
        }

        factory.UserName = _rabbitConfig.Username;
        factory.Password = _rabbitConfig.Password;
        
        _logger?.LogDebug("Configured RabbitMQ basic authentication for user: {Username}", _rabbitConfig.Username);
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

    private async void OnTokenRefreshed(object? sender, KeycloakTokenResponse tokenResponse)
    {
        if (_rabbitConfig.UseKeycloakAuthentication && _connection?.IsOpen == true)
        {
            _logger?.LogInformation("Keycloak token refreshed, RabbitMQ connection will be renewed on next access");
            
            // Close current connection to force renewal with new token
            try
            {
                _connection?.Close();
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Error closing RabbitMQ connection during token refresh");
            }
        }
    }

    /// <summary>
    /// Closes the current RabbitMQ connection
    /// </summary>
    public async Task CloseConnectionAsync()
    {
        await _connectionSemaphore.WaitAsync();
        try
        {
            if (_connection?.IsOpen == true)
            {
                _connection.Close();
                _logger?.LogInformation("RabbitMQ connection closed");
            }
        }
        finally
        {
            _connectionSemaphore.Release();
        }
    }

    public void Dispose()
    {
        if (_disposed) return;

        _tokenManager.TokenRefreshed -= OnTokenRefreshed;
        
        try
        {
            _connection?.Close();
            _connection?.Dispose();
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Error disposing RabbitMQ connection");
        }

        _connectionSemaphore.Dispose();
        _disposed = true;
    }
}