using Microsoft.AspNetCore.Mvc;

namespace KeyCloackRabbitMQ.DemoApplication.Controllers;

[ApiController]
[Route("api/[controller]")]
public class TestController : ControllerBase
{
    private readonly ILogger<TestController> _logger;

    public TestController(ILogger<TestController> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Simple test endpoint to verify application is working
    /// </summary>
    [HttpGet]
    public ActionResult<object> Get()
    {
        _logger.LogInformation("Test endpoint called");
        
        return Ok(new
        {
            message = "Application is working!",
            timestamp = DateTime.UtcNow,
            environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT"),
            machineName = Environment.MachineName
        });
    }

    /// <summary>
    /// Simple ping endpoint
    /// </summary>
    [HttpGet("ping")]
    public ActionResult<object> Ping()
    {
        return Ok(new { status = "pong", timestamp = DateTime.UtcNow });
    }
}