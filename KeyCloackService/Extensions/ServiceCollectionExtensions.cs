using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using KeyCloackService.Models;
using KeyCloackService.RabbitMQ;
using KeyCloackService.MassTransit;

namespace KeyCloackService.Extensions;

/// <summary>
/// Extension methods for configuring RabbitMQ with Keycloak authentication in dependency injection
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds KeycloakService with RabbitMQ support to the service collection
    /// </summary>
    /// <param name="services">Service collection</param>
    /// <param name="keycloakConfigSection">Configuration section for Keycloak settings</param>
    /// <param name="rabbitMQConfigSection">Configuration section for RabbitMQ settings</param>
    /// <returns>Service collection for chaining</returns>
    public static IServiceCollection AddKeycloakRabbitMQ(
        this IServiceCollection services,
        string keycloakConfigSection = "Keycloak",
        string rabbitMQConfigSection = "RabbitMQ")
    {
        // Register Keycloak configuration
        services.AddSingleton<KeycloakConfig>(serviceProvider =>
        {
            var configuration = serviceProvider.GetRequiredService<IConfiguration>();
            var section = configuration.GetSection(keycloakConfigSection);
            
            var serverUrl = section["ServerUrl"] ?? throw new ArgumentException("Keycloak ServerUrl is required");
            var realm = section["Realm"] ?? throw new ArgumentException("Keycloak Realm is required");
            var clientId = section["ClientId"] ?? throw new ArgumentException("Keycloak ClientId is required");
            
            var config = new KeycloakConfig
            {
                ServerUrl = serverUrl,
                Realm = realm,
                ClientId = clientId
            };
            
            section.Bind(config);
            return config;
        });

        // Register RabbitMQ configuration
        services.AddSingleton<RabbitMQConfig>(serviceProvider =>
        {
            var configuration = serviceProvider.GetRequiredService<IConfiguration>();
            var config = new RabbitMQConfig();
            configuration.GetSection(rabbitMQConfigSection).Bind(config);
            return config;
        });

        // Register Keycloak token manager as Singleton - needed for startup initialization
        services.AddSingleton<KeycloakTokenManager>();

        // Register RabbitMQ services as Singleton - needed for startup initialization
        services.AddSingleton<KeycloakRabbitMQConnectionFactory>();
        services.AddSingleton<KeycloakRabbitMQService>();

        return services;
    }

    /// <summary>
    /// Adds KeycloakService with RabbitMQ support to the service collection with custom configurations
    /// </summary>
    /// <param name="services">Service collection</param>
    /// <param name="keycloakConfig">Keycloak configuration</param>
    /// <param name="rabbitMQConfig">RabbitMQ configuration</param>
    /// <returns>Service collection for chaining</returns>
    public static IServiceCollection AddKeycloakRabbitMQ(
        this IServiceCollection services,
        KeycloakConfig keycloakConfig,
        RabbitMQConfig rabbitMQConfig)
    {
        // Register configurations
        services.AddSingleton(keycloakConfig);
        services.AddSingleton(rabbitMQConfig);

        // Register Keycloak token manager as Singleton
        services.AddSingleton<KeycloakTokenManager>();

        // Register RabbitMQ services as Singleton
        services.AddSingleton<KeycloakRabbitMQConnectionFactory>();
        services.AddSingleton<KeycloakRabbitMQService>();

        return services;
    }

    /// <summary>
    /// Adds KeycloakService with RabbitMQ support to the service collection with configuration actions
    /// </summary>
    /// <param name="services">Service collection</param>
    /// <param name="configureKeycloak">Action to configure Keycloak settings</param>
    /// <param name="configureRabbitMQ">Action to configure RabbitMQ settings</param>
    /// <returns>Service collection for chaining</returns>
    public static IServiceCollection AddKeycloakRabbitMQ(
        this IServiceCollection services,
        Action<KeycloakConfig> configureKeycloak,
        Action<RabbitMQConfig> configureRabbitMQ)
    {
        // Register configurations with actions - we need a temporary config first
        services.AddSingleton<KeycloakConfig>(serviceProvider =>
        {
            // Create with minimal required properties, then let the action configure the rest
            var config = new KeycloakConfig
            {
                ServerUrl = "temp",
                Realm = "temp", 
                ClientId = "temp"
            };
            configureKeycloak(config);
            return config;
        });

        services.AddSingleton<RabbitMQConfig>(serviceProvider =>
        {
            var config = new RabbitMQConfig();
            configureRabbitMQ(config);
            return config;
        });

        // Register Keycloak token manager as Singleton
        services.AddSingleton<KeycloakTokenManager>();

        // Register RabbitMQ services as Singleton
        services.AddSingleton<KeycloakRabbitMQConnectionFactory>();
        services.AddSingleton<KeycloakRabbitMQService>();

        return services;
    }

    /// <summary>
    /// Adds KeycloakService with MassTransit support for RabbitMQ authentication
    /// </summary>
    /// <param name="services">Service collection</param>
    /// <param name="keycloakConfigSection">Configuration section for Keycloak settings</param>
    /// <returns>Service collection for chaining</returns>
    public static IServiceCollection AddKeycloakMassTransit(
        this IServiceCollection services,
        string keycloakConfigSection = "Keycloak")
    {
        // Register Keycloak configuration
        services.AddSingleton<KeycloakConfig>(serviceProvider =>
        {
            var configuration = serviceProvider.GetRequiredService<IConfiguration>();
            var section = configuration.GetSection(keycloakConfigSection);
            
            var serverUrl = section["ServerUrl"] ?? throw new ArgumentException("Keycloak ServerUrl is required");
            var realm = section["Realm"] ?? throw new ArgumentException("Keycloak Realm is required");
            var clientId = section["ClientId"] ?? throw new ArgumentException("Keycloak ClientId is required");
            
            var config = new KeycloakConfig
            {
                ServerUrl = serverUrl,
                Realm = realm,
                ClientId = clientId
            };
            
            section.Bind(config);
            return config;
        });

        // Register Keycloak token manager as Singleton
        services.AddSingleton<KeycloakTokenManager>();

        // Register MassTransit credentials provider
        services.AddScoped<KeycloakCredentialsProvider>();

        return services;
    }

    /// <summary>
    /// Adds KeycloakService with MassTransit support using custom Keycloak configuration
    /// </summary>
    /// <param name="services">Service collection</param>
    /// <param name="keycloakConfig">Keycloak configuration</param>
    /// <returns>Service collection for chaining</returns>
    public static IServiceCollection AddKeycloakMassTransit(
        this IServiceCollection services,
        KeycloakConfig keycloakConfig)
    {
        // Register configuration
        services.AddSingleton(keycloakConfig);

        // Register Keycloak token manager as Singleton
        services.AddSingleton<KeycloakTokenManager>();

        // Register MassTransit credentials provider
        services.AddScoped<KeycloakCredentialsProvider>();

        return services;
    }

    /// <summary>
    /// Adds KeycloakService with MassTransit support using configuration action
    /// </summary>
    /// <param name="services">Service collection</param>
    /// <param name="configureKeycloak">Action to configure Keycloak settings</param>
    /// <returns>Service collection for chaining</returns>
    public static IServiceCollection AddKeycloakMassTransit(
        this IServiceCollection services,
        Action<KeycloakConfig> configureKeycloak)
    {
        // Register configuration with action
        services.AddSingleton<KeycloakConfig>(serviceProvider =>
        {
            // Create with minimal required properties, then let the action configure the rest
            var config = new KeycloakConfig
            {
                ServerUrl = "temp",
                Realm = "temp", 
                ClientId = "temp"
            };
            configureKeycloak(config);
            return config;
        });

        // Register Keycloak token manager as Singleton
        services.AddSingleton<KeycloakTokenManager>();

        // Register MassTransit credentials provider
        services.AddScoped<KeycloakCredentialsProvider>();

        return services;
    }
}