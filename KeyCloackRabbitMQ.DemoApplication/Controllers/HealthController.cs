using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using KeyCloackRabbitMQ.DemoApplication.Models;
using HealthCheckStatus = Microsoft.Extensions.Diagnostics.HealthChecks.HealthStatus;

namespace KeyCloackRabbitMQ.DemoApplication.Controllers;

[ApiController]
[Route("api/[controller]")]
public class HealthController : ControllerBase
{
    private readonly HealthCheckService? _healthCheckService;
    private readonly ILogger<HealthController> _logger;

    public HealthController(IServiceProvider serviceProvider, ILogger<HealthController> logger)
    {
        _healthCheckService = serviceProvider.GetService<HealthCheckService>();
        _logger = logger;
    }

    /// <summary>
    /// Get overall health status
    /// </summary>
    [HttpGet]
    public async Task<ActionResult<ApiResponse<object>>> GetHealth()
    {
        try
        {
            if (_healthCheckService == null)
            {
                var basicResponse = new
                {
                    Status = "Healthy",
                    Message = "Application is running but health checks are not configured",
                    Timestamp = DateTime.UtcNow,
                    Services = new[] { "Application Core" }
                };
                
                return Ok(ApiResponse<object>.SuccessResponse(basicResponse, "Basic health check passed"));
            }

            var healthReport = await _healthCheckService.CheckHealthAsync();

            var response = new
            {
                Status = healthReport.Status.ToString(),
                TotalDuration = healthReport.TotalDuration,
                Checks = healthReport.Entries.Select(entry => new Models.HealthStatus
                {
                    Service = entry.Key,
                    IsHealthy = entry.Value.Status == HealthCheckStatus.Healthy,
                    Status = entry.Value.Status.ToString(),
                    Details = entry.Value.Description
                }).ToList()
            };

            if (healthReport.Status == HealthCheckStatus.Healthy)
            {
                _logger.LogDebug("Health check passed for all services");
                return Ok(ApiResponse<object>.SuccessResponse(response, "All services are healthy"));
            }
            else
            {
                _logger.LogWarning("Health check failed for some services: {Status}", healthReport.Status);
                return StatusCode(503, ApiResponse<object>.SuccessResponse(response, "Some services are unhealthy"));
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Health check failed with exception");
            
            var errorResponse = new
            {
                Status = "Unhealthy",
                Message = "Health check system failed",
                Error = ex.Message,
                Timestamp = DateTime.UtcNow
            };
            
            return StatusCode(500, ApiResponse<object>.ErrorResponse($"Health check failed: {ex.Message}"));
        }
    }

    /// <summary>
    /// Get Keycloak health status
    /// </summary>
    [HttpGet("keycloak")]
    public async Task<ActionResult<ApiResponse<Models.HealthStatus>>> GetKeycloakHealth()
    {
        try
        {
            if (_healthCheckService == null)
            {
                var status = new Models.HealthStatus
                {
                    Service = "Keycloak",
                    IsHealthy = false,
                    Status = "Unknown",
                    Details = "Health check service not available"
                };
                return Ok(ApiResponse<Models.HealthStatus>.SuccessResponse(status, "Health check service not configured"));
            }

            var healthReport = await _healthCheckService.CheckHealthAsync(
                healthCheck => healthCheck.Name == "keycloak");

            var keycloakEntry = healthReport.Entries.FirstOrDefault();

            if (keycloakEntry.Key != null)
            {
                var status = new Models.HealthStatus
                {
                    Service = "Keycloak",
                    IsHealthy = keycloakEntry.Value.Status == HealthCheckStatus.Healthy,
                    Status = keycloakEntry.Value.Status.ToString(),
                    Details = keycloakEntry.Value.Description
                };

                if (status.IsHealthy)
                {
                    return Ok(ApiResponse<Models.HealthStatus>.SuccessResponse(status, "Keycloak is healthy"));
                }
                else
                {
                    return StatusCode(503, ApiResponse<Models.HealthStatus>.SuccessResponse(status, "Keycloak is unhealthy"));
                }
            }
            else
            {
                var status = new Models.HealthStatus
                {
                    Service = "Keycloak",
                    IsHealthy = false,
                    Status = "Not Configured",
                    Details = "Keycloak health check not found or not configured"
                };
                return NotFound(ApiResponse<Models.HealthStatus>.SuccessResponse(status, "Keycloak health check not found"));
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Keycloak health check failed");
            return StatusCode(500, ApiResponse<Models.HealthStatus>.ErrorResponse($"Keycloak health check failed: {ex.Message}"));
        }
    }

    /// <summary>
    /// Get RabbitMQ health status
    /// </summary>
    [HttpGet("rabbitmq")]
    public async Task<ActionResult<ApiResponse<Models.HealthStatus>>> GetRabbitMQHealth()
    {
        try
        {
            if (_healthCheckService == null)
            {
                var status = new Models.HealthStatus
                {
                    Service = "RabbitMQ",
                    IsHealthy = false,
                    Status = "Unknown",
                    Details = "Health check service not available"
                };
                return Ok(ApiResponse<Models.HealthStatus>.SuccessResponse(status, "Health check service not configured"));
            }

            var healthReport = await _healthCheckService.CheckHealthAsync(
                healthCheck => healthCheck.Name == "rabbitmq");

            var rabbitEntry = healthReport.Entries.FirstOrDefault();

            if (rabbitEntry.Key != null)
            {
                var status = new Models.HealthStatus
                {
                    Service = "RabbitMQ",
                    IsHealthy = rabbitEntry.Value.Status == HealthCheckStatus.Healthy,
                    Status = rabbitEntry.Value.Status.ToString(),
                    Details = rabbitEntry.Value.Description
                };

                if (status.IsHealthy)
                {
                    return Ok(ApiResponse<Models.HealthStatus>.SuccessResponse(status, "RabbitMQ is healthy"));
                }
                else
                {
                    return StatusCode(503, ApiResponse<Models.HealthStatus>.SuccessResponse(status, "RabbitMQ is unhealthy"));
                }
            }
            else
            {
                var status = new Models.HealthStatus
                {
                    Service = "RabbitMQ",
                    IsHealthy = false,
                    Status = "Not Configured",
                    Details = "RabbitMQ health check not found or not configured"
                };
                return NotFound(ApiResponse<Models.HealthStatus>.SuccessResponse(status, "RabbitMQ health check not found"));
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "RabbitMQ health check failed");
            return StatusCode(500, ApiResponse<Models.HealthStatus>.ErrorResponse($"RabbitMQ health check failed: {ex.Message}"));
        }
    }
}