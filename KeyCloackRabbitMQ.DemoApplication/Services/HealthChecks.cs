using KeyCloackService;
using KeyCloackService.RabbitMQ;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace KeyCloackRabbitMQ.DemoApplication.Services;

/// <summary>
/// Health check for Keycloak authentication
/// </summary>
public class KeycloakHealthCheck : IHealthCheck
{
    private readonly KeycloakTokenManager _tokenManager;
    private readonly ILogger<KeycloakHealthCheck> _logger;

    public KeycloakHealthCheck(KeycloakTokenManager tokenManager, ILogger<KeycloakHealthCheck> logger)
    {
        _tokenManager = tokenManager;
        _logger = logger;
    }

    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            // Try to get a token to verify Keycloak connectivity
            var token = await _tokenManager.GetAccessTokenAsync(cancellationToken);
            
            if (!string.IsNullOrEmpty(token))
            {
                _logger.LogDebug("Keycloak health check passed - token received");
                return HealthCheckResult.Healthy("Keycloak is accessible and authentication is working");
            }
            else
            {
                _logger.LogWarning("Keycloak health check failed - empty token received");
                return HealthCheckResult.Unhealthy("Keycloak authentication failed - empty token");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Keycloak health check failed with exception");
            return HealthCheckResult.Unhealthy($"Keycloak authentication failed: {ex.Message}", ex);
        }
    }
}

/// <summary>
/// Health check for RabbitMQ connection
/// </summary>
public class RabbitMQHealthCheck : IHealthCheck
{
    private readonly KeycloakRabbitMQConnectionFactory _connectionFactory;
    private readonly ILogger<RabbitMQHealthCheck> _logger;

    public RabbitMQHealthCheck(KeycloakRabbitMQConnectionFactory connectionFactory, ILogger<RabbitMQHealthCheck> logger)
    {
        _connectionFactory = connectionFactory;
        _logger = logger;
    }

    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            using var connection = await _connectionFactory.CreateConnectionAsync(cancellationToken);
            
            if (connection.IsOpen)
            {
                _logger.LogDebug("RabbitMQ health check passed - connection is open");
                return HealthCheckResult.Healthy("RabbitMQ connection is healthy");
            }
            else
            {
                _logger.LogWarning("RabbitMQ health check failed - connection is closed");
                return HealthCheckResult.Unhealthy("RabbitMQ connection is closed");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "RabbitMQ health check failed with exception");
            return HealthCheckResult.Unhealthy($"RabbitMQ connection failed: {ex.Message}", ex);
        }
    }
}