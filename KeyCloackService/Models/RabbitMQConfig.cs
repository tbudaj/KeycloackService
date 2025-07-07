namespace KeyCloackService.Models;

/// <summary>
/// Configuration for RabbitMQ connection with Keycloak authentication
/// </summary>
public class RabbitMQConfig
{
    /// <summary>
    /// RabbitMQ server hostname
    /// </summary>
    public string HostName { get; set; } = "localhost";

    /// <summary>
    /// RabbitMQ server port
    /// </summary>
    public int Port { get; set; } = 5672;

    /// <summary>
    /// Virtual host to connect to
    /// </summary>
    public string VirtualHost { get; set; } = "/";

    /// <summary>
    /// Connection timeout
    /// </summary>
    public TimeSpan RequestedConnectionTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Socket read timeout
    /// </summary>
    public TimeSpan SocketReadTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Socket write timeout
    /// </summary>
    public TimeSpan SocketWriteTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Enable SSL/TLS
    /// </summary>
    public bool UseSsl { get; set; } = false;

    /// <summary>
    /// SSL server name (required when UseSsl is true)
    /// </summary>
    public string? SslServerName { get; set; }

    /// <summary>
    /// Whether to automatically recover connections
    /// </summary>
    public bool AutomaticRecoveryEnabled { get; set; } = true;

    /// <summary>
    /// Network recovery interval
    /// </summary>
    public TimeSpan NetworkRecoveryInterval { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Whether to use Keycloak token for authentication
    /// When true, Username and Password are ignored
    /// </summary>
    public bool UseKeycloakAuthentication { get; set; } = true;

    /// <summary>
    /// RabbitMQ username (used when UseKeycloakAuthentication is false)
    /// </summary>
    public string? Username { get; set; }

    /// <summary>
    /// RabbitMQ password (used when UseKeycloakAuthentication is false)
    /// </summary>
    public string? Password { get; set; }
}