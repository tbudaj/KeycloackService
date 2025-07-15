using KeyCloackService.MassTransit;
using Microsoft.AspNetCore.Mvc;

namespace KeyCloackRabbitMQ.DemoApplication.Controllers;

[ApiController]
[Route("api/[controller]")]
public class MassTransitDemoController : ControllerBase
{
    private readonly KeycloakCredentialsProvider _credentialsProvider;
    private readonly ILogger<MassTransitDemoController> _logger;

    public MassTransitDemoController(
        KeycloakCredentialsProvider credentialsProvider, 
        ILogger<MassTransitDemoController> logger)
    {
        _credentialsProvider = credentialsProvider;
        _logger = logger;
    }

    /// <summary>
    /// Demonstrates how to get Keycloak credentials for MassTransit
    /// </summary>
    [HttpGet("credentials")]
    public async Task<IActionResult> GetCredentials()
    {
        try
        {
            var credentials = await _credentialsProvider.GetCredentialsAsync();
            
            return Ok(new
            {
                success = true,
                data = new
                {
                    username = credentials.UserName,
                    hasPassword = !string.IsNullOrEmpty(credentials.Password),
                    passwordLength = credentials.Password?.Length ?? 0,
                    tokenPreview = credentials.Password?[..Math.Min(50, credentials.Password.Length)] + "...",
                    message = "These credentials can be used with MassTransit RabbitMQ configuration"
                },
                message = "Keycloak credentials retrieved successfully"
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get Keycloak credentials");
            return StatusCode(500, new
            {
                success = false,
                message = "Failed to retrieve Keycloak credentials",
                error = ex.Message
            });
        }
    }

    /// <summary>
    /// Shows example of MassTransit configuration code with Keycloak
    /// </summary>
    [HttpGet("configuration-example")]
    public IActionResult GetConfigurationExample()
    {
        var example = @"
// Add to Program.cs

using KeyCloackService.Extensions;
using KeyCloackService.MassTransit;

// Register Keycloak for MassTransit
builder.Services.AddKeycloakMassTransit();

// Configure MassTransit with Keycloak
builder.Services.AddMassTransit<ISavingsAccountBus>(cfg =>
{
    cfg.SetEndpointNameFormatter(new KebabCaseEndpointNameFormatter(true));

    cfg.UsingRabbitMq((busContext, rabbitCfg) =>
    {
        // Configure topology
        rabbitCfg.ConfigureScbPublishTopologyFor<Contract.SavingsAccount.Tool.Ping>();
        rabbitCfg.ConfigureScbPublishTopologyFor<Contract.SavingsAccount.Client.StartedLogging>();

        // REPLACE UserPasswordProvider with Keycloak
        var (username, password) = busContext.GetKeycloakCredentials();
        
        rabbitCfg.Host(builder.Configuration[""RabbitMQ:HostName""]!, h =>
        {
            h.Username(username);        // Username from JWT token
            h.Password(password);        // JWT token as password
        });

        rabbitCfg.UseEntityFrameworkCoreAuditStore<AuditDbContext>(
            builder.Configuration.GetConnectionString(""MessageBrokerDb"")!, 
            ""AuditTable"");
    });
});
";

        return Ok(new
        {
            success = true,
            data = new
            {
                title = "MassTransit Configuration with Keycloak JWT",
                description = "Replace UserPasswordProvider with KeycloakCredentialsProvider",
                code = example,
                benefits = new[]
                {
                    "Centralized identity management",
                    "Automatic token refresh",
                    "Better security with JWT",
                    "OAuth2/OIDC compliance",
                    "Audit trail in Keycloak"
                }
            },
            message = "Configuration example retrieved successfully"
        });
    }

    /// <summary>
    /// Health check for Keycloak credentials provider
    /// </summary>
    [HttpGet("health")]
    public async Task<IActionResult> GetHealth()
    {
        try
        {
            var credentials = await _credentialsProvider.GetCredentialsAsync();
            var isHealthy = !string.IsNullOrEmpty(credentials.UserName) && !string.IsNullOrEmpty(credentials.Password);

            return Ok(new
            {
                success = true,
                data = new
                {
                    status = isHealthy ? "Healthy" : "Unhealthy",
                    hasUsername = !string.IsNullOrEmpty(credentials.UserName),
                    hasToken = !string.IsNullOrEmpty(credentials.Password),
                    message = isHealthy 
                        ? "Keycloak credentials provider is working correctly"
                        : "Keycloak credentials provider has issues"
                },
                message = "Health check completed"
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Health check failed for Keycloak credentials provider");
            return StatusCode(500, new
            {
                success = false,
                data = new
                {
                    status = "Unhealthy",
                    error = ex.Message
                },
                message = "Health check failed"
            });
        }
    }
}