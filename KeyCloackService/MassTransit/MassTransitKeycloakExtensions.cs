using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace KeyCloackService.MassTransit;

/// <summary>
/// Extension methods for configuring MassTransit with Keycloak authentication
/// </summary>
public static class MassTransitKeycloakExtensions
{
    /// <summary>
    /// Configures RabbitMQ connection with Keycloak JWT authentication
    /// This method should be called within MassTransit UsingRabbitMq configuration
    /// </summary>
    /// <param name="serviceProvider">Service provider</param>
    /// <param name="hostName">RabbitMQ host name</param>
    /// <param name="port">RabbitMQ port</param>
    /// <param name="virtualHost">Virtual host</param>
    /// <returns>Configuration action that can be used with MassTransit</returns>
    public static Action<object> UseKeycloakAuthentication(
        this IServiceProvider serviceProvider,
        string hostName,
        int port = 5672,
        string virtualHost = "/")
    {
        return (object rabbitConfigurator) =>
        {
            var credentialsProvider = serviceProvider.GetRequiredService<KeycloakCredentialsProvider>();
            var logger = serviceProvider.GetService<ILogger<KeycloakCredentialsProvider>>();

            try
            {
                // Get credentials synchronously (this is needed for MassTransit configuration)
                var credentials = credentialsProvider.GetCredentials();
                
                logger?.LogInformation("Configuring MassTransit RabbitMQ with Keycloak JWT for user: {Username}", 
                    credentials.UserName);

                // Configure the host with Keycloak credentials using reflection
                var configuratorType = rabbitConfigurator.GetType();
                var hostMethod = configuratorType.GetMethod("Host", new[] { typeof(string), typeof(int), typeof(string), typeof(Action<object>) });
                
                if (hostMethod != null)
                {
                    Action<object> hostConfig = (object h) =>
                    {
                        var hostType = h.GetType();
                        var usernameMethod = hostType.GetMethod("Username", new[] { typeof(string) });
                        var passwordMethod = hostType.GetMethod("Password", new[] { typeof(string) });
                        
                        usernameMethod?.Invoke(h, new object[] { credentials.UserName });
                        passwordMethod?.Invoke(h, new object[] { credentials.Password });
                    };
                    
                    hostMethod.Invoke(rabbitConfigurator, new object[] { hostName, port, virtualHost, hostConfig });
                }
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "Failed to configure MassTransit with Keycloak authentication");
                throw new InvalidOperationException("Failed to configure MassTransit with Keycloak authentication", ex);
            }
        };
    }

    /// <summary>
    /// Gets Keycloak credentials for manual MassTransit configuration
    /// </summary>
    /// <param name="serviceProvider">Service provider</param>
    /// <returns>Username and JWT token for RabbitMQ authentication</returns>
    public static (string Username, string Password) GetKeycloakCredentials(this IServiceProvider serviceProvider)
    {
        var credentialsProvider = serviceProvider.GetRequiredService<KeycloakCredentialsProvider>();
        var credentials = credentialsProvider.GetCredentials();
        
        return (credentials.UserName, credentials.Password);
    }

    /// <summary>
    /// Gets Keycloak credentials asynchronously for manual MassTransit configuration
    /// </summary>
    /// <param name="serviceProvider">Service provider</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Username and JWT token for RabbitMQ authentication</returns>
    public static async Task<(string Username, string Password)> GetKeycloakCredentialsAsync(
        this IServiceProvider serviceProvider, 
        CancellationToken cancellationToken = default)
    {
        var credentialsProvider = serviceProvider.GetRequiredService<KeycloakCredentialsProvider>();
        var credentials = await credentialsProvider.GetCredentialsAsync(cancellationToken);
        
        return (credentials.UserName, credentials.Password);
    }
}