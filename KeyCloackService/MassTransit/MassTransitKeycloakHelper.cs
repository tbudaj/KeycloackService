using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System.Net;

namespace KeyCloackService.MassTransit;

/// <summary>
/// Helper class for configuring MassTransit RabbitMQ with Keycloak authentication
/// </summary>
public static class MassTransitKeycloakHelper
{
    /// <summary>
    /// Configures RabbitMQ host with Keycloak JWT authentication
    /// </summary>
    /// <param name="serviceProvider">Service provider to resolve dependencies</param>
    /// <param name="hostConfigurator">Host configurator action</param>
    /// <param name="hostName">RabbitMQ host name</param>
    /// <param name="port">RabbitMQ port (default: 5672)</param>
    /// <param name="virtualHost">Virtual host (default: "/")</param>
    public static void ConfigureKeycloakHost(
        IServiceProvider serviceProvider,
        Action<object> hostConfigurator,
        string hostName,
        int port = 5672,
        string virtualHost = "/")
    {
        var credentialsProvider = serviceProvider.GetRequiredService<KeycloakCredentialsProvider>();
        var logger = serviceProvider.GetService<ILogger>();

        try
        {
            // Get credentials from Keycloak
            var credentials = credentialsProvider.GetCredentials();
            
            logger?.LogInformation("Configuring MassTransit RabbitMQ with Keycloak JWT authentication for user: {Username}", 
                credentials.UserName);

            // Configure host using reflection to work with any MassTransit host configurator type
            var hostConfiguratorType = hostConfigurator.Target?.GetType();
            var hostMethod = hostConfiguratorType?.GetMethod("Host", new[] { typeof(string), typeof(int), typeof(string), typeof(Action<object>) });
            
            if (hostMethod != null)
            {
                hostMethod.Invoke(hostConfigurator.Target, new object[] 
                { 
                    hostName, 
                    port, 
                    virtualHost, 
                    new Action<object>(h => ConfigureCredentials(h, credentials, logger))
                });
            }
            else
            {
                logger?.LogWarning("Could not find Host method on configurator type: {Type}", hostConfiguratorType?.Name);
            }
        }
        catch (Exception ex)
        {
            logger?.LogError(ex, "Failed to configure MassTransit RabbitMQ with Keycloak authentication");
            throw;
        }
    }

    /// <summary>
    /// Configures RabbitMQ host with Keycloak JWT authentication (async version)
    /// </summary>
    /// <param name="serviceProvider">Service provider to resolve dependencies</param>
    /// <param name="hostConfigurator">Host configurator action</param>
    /// <param name="hostName">RabbitMQ host name</param>
    /// <param name="port">RabbitMQ port (default: 5672)</param>
    /// <param name="virtualHost">Virtual host (default: "/")</param>
    /// <param name="cancellationToken">Cancellation token</param>
    public static async Task ConfigureKeycloakHostAsync(
        IServiceProvider serviceProvider,
        Action<object> hostConfigurator,
        string hostName,
        int port = 5672,
        string virtualHost = "/",
        CancellationToken cancellationToken = default)
    {
        var credentialsProvider = serviceProvider.GetRequiredService<KeycloakCredentialsProvider>();
        var logger = serviceProvider.GetService<ILogger>();

        try
        {
            // Get credentials from Keycloak asynchronously
            var credentials = await credentialsProvider.GetCredentialsAsync(cancellationToken);
            
            logger?.LogInformation("Configuring MassTransit RabbitMQ with Keycloak JWT authentication for user: {Username}", 
                credentials.UserName);

            // Configure host using reflection to work with any MassTransit host configurator type
            var hostConfiguratorType = hostConfigurator.Target?.GetType();
            var hostMethod = hostConfiguratorType?.GetMethod("Host", new[] { typeof(string), typeof(int), typeof(string), typeof(Action<object>) });
            
            if (hostMethod != null)
            {
                hostMethod.Invoke(hostConfigurator.Target, new object[] 
                { 
                    hostName, 
                    port, 
                    virtualHost, 
                    new Action<object>(h => ConfigureCredentials(h, credentials, logger))
                });
            }
            else
            {
                logger?.LogWarning("Could not find Host method on configurator type: {Type}", hostConfiguratorType?.Name);
            }
        }
        catch (Exception ex)
        {
            logger?.LogError(ex, "Failed to configure MassTransit RabbitMQ with Keycloak authentication");
            throw;
        }
    }

    private static void ConfigureCredentials(object hostConfigurator, NetworkCredential credentials, ILogger? logger)
    {
        try
        {
            var configuratorType = hostConfigurator.GetType();
            
            // Set username
            var usernameMethod = configuratorType.GetMethod("Username", new[] { typeof(string) });
            usernameMethod?.Invoke(hostConfigurator, new object[] { credentials.UserName });
            
            // Set password (JWT token)
            var passwordMethod = configuratorType.GetMethod("Password", new[] { typeof(string) });
            passwordMethod?.Invoke(hostConfigurator, new object[] { credentials.Password });
            
            logger?.LogDebug("Successfully configured MassTransit credentials for user: {Username}", credentials.UserName);
        }
        catch (Exception ex)
        {
            logger?.LogError(ex, "Failed to configure MassTransit credentials");
            throw;
        }
    }
}