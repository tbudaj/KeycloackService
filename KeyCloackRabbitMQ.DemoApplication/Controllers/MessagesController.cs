using Microsoft.AspNetCore.Mvc;
using KeyCloackRabbitMQ.DemoApplication.Models;
using KeyCloackRabbitMQ.DemoApplication.Services;

namespace KeyCloackRabbitMQ.DemoApplication.Controllers;

[ApiController]
[Route("api/[controller]")]
public class MessagesController : ControllerBase
{
    private readonly MessageProducerService _producerService;
    private readonly ILogger<MessagesController> _logger;

    public MessagesController(MessageProducerService producerService, ILogger<MessagesController> logger)
    {
        _producerService = producerService;
        _logger = logger;
    }

    /// <summary>
    /// Send a test message to the queue
    /// </summary>
    [HttpPost("test")]
    public async Task<ActionResult<ApiResponse<TestMessage>>> SendTestMessage([FromBody] SendMessageRequest request)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(request.Content))
            {
                return BadRequest(ApiResponse<TestMessage>.ErrorResponse("Content cannot be empty"));
            }

            var message = await _producerService.SendTestMessageAsync(request.Content, request.Metadata);
            
            _logger.LogInformation("Test message sent via API: {MessageId}", message.Id);
            
            return Ok(ApiResponse<TestMessage>.SuccessResponse(message, "Test message sent successfully"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send test message");
            return StatusCode(500, ApiResponse<TestMessage>.ErrorResponse($"Failed to send message: {ex.Message}"));
        }
    }

    /// <summary>
    /// Send an order to the queue
    /// </summary>
    [HttpPost("order")]
    public async Task<ActionResult<ApiResponse<Order>>> SendOrder([FromBody] Order order)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(order.CustomerName))
            {
                return BadRequest(ApiResponse<Order>.ErrorResponse("Customer name is required"));
            }

            if (string.IsNullOrWhiteSpace(order.ProductName))
            {
                return BadRequest(ApiResponse<Order>.ErrorResponse("Product name is required"));
            }

            if (order.Amount <= 0)
            {
                return BadRequest(ApiResponse<Order>.ErrorResponse("Amount must be greater than 0"));
            }

            var sentOrder = await _producerService.SendOrderAsync(order);
            
            _logger.LogInformation("Order sent via API: {OrderId}", sentOrder.Id);
            
            return Ok(ApiResponse<Order>.SuccessResponse(sentOrder, "Order sent successfully"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send order");
            return StatusCode(500, ApiResponse<Order>.ErrorResponse($"Failed to send order: {ex.Message}"));
        }
    }

    /// <summary>
    /// Send a notification
    /// </summary>
    [HttpPost("notification")]
    public async Task<ActionResult<ApiResponse<object>>> SendNotification([FromBody] object notification)
    {
        try
        {
            // Extract notification data
            var title = "Demo Notification";
            var body = notification?.ToString() ?? "Test notification";
            var recipient = "demo@example.com";

            await _producerService.SendNotificationAsync(title, body, recipient);
            
            _logger.LogInformation("Notification sent via API");
            
            return Ok(ApiResponse<object>.SuccessResponse(new { Title = title, Body = body, Recipient = recipient }, 
                "Notification sent successfully"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send notification");
            return StatusCode(500, ApiResponse<object>.ErrorResponse($"Failed to send notification: {ex.Message}"));
        }
    }

    /// <summary>
    /// Send multiple test messages at once
    /// </summary>
    [HttpPost("test/bulk")]
    public async Task<ActionResult<ApiResponse<List<TestMessage>>>> SendBulkTestMessages([FromBody] List<SendMessageRequest> requests)
    {
        try
        {
            var messages = new List<TestMessage>();

            foreach (var request in requests)
            {
                if (!string.IsNullOrWhiteSpace(request.Content))
                {
                    var message = await _producerService.SendTestMessageAsync(request.Content, request.Metadata);
                    messages.Add(message);
                }
            }

            _logger.LogInformation("Bulk test messages sent: {Count}", messages.Count);
            
            return Ok(ApiResponse<List<TestMessage>>.SuccessResponse(messages, 
                $"{messages.Count} test messages sent successfully"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send bulk test messages");
            return StatusCode(500, ApiResponse<List<TestMessage>>.ErrorResponse($"Failed to send bulk messages: {ex.Message}"));
        }
    }

    /// <summary>
    /// Get debug information about message queues
    /// </summary>
    [HttpGet("debug")]
    public async Task<ActionResult<ApiResponse<object>>> GetDebugInfo()
    {
        try
        {
            var debugInfo = new
            {
                Message = "Debug information for message processing",
                Timestamp = DateTime.UtcNow,
                Instructions = new[]
                {
                    "1. Check if consumers are registered",
                    "2. Verify RabbitMQ queue states",
                    "3. Test direct queue publishing",
                    "4. Check application logs for errors"
                },
                TestCommands = new
                {
                    DirectPublish = "Will publish directly to queue instead of exchange",
                    QueueStatus = "Check RabbitMQ Management UI for queue details"
                }
            };

            return Ok(ApiResponse<object>.SuccessResponse(debugInfo, "Debug information retrieved"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get debug information");
            return StatusCode(500, ApiResponse<object>.ErrorResponse($"Failed to get debug info: {ex.Message}"));
        }
    }

    /// <summary>
    /// Send test message directly to queue (bypassing exchange)
    /// </summary>
    [HttpPost("test/direct")]
    public async Task<ActionResult<ApiResponse<TestMessage>>> SendTestMessageDirect([FromBody] SendMessageRequest request)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(request.Content))
            {
                return BadRequest(ApiResponse<TestMessage>.ErrorResponse("Content cannot be empty"));
            }

            // Create test message
            var message = new TestMessage
            {
                Content = request.Content,
                Metadata = request.Metadata ?? new Dictionary<string, object>()
            };

            // Send directly to queue using default exchange
            await _producerService.SendTestMessageDirectAsync(message);
            
            _logger.LogInformation("Test message sent DIRECTLY to queue: {MessageId}", message.Id);
            
            return Ok(ApiResponse<TestMessage>.SuccessResponse(message, "Test message sent directly to queue"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send test message directly");
            return StatusCode(500, ApiResponse<TestMessage>.ErrorResponse($"Failed to send direct message: {ex.Message}"));
        }
    }

    /// <summary>
    /// Test RabbitMQ connection and consumer status
    /// </summary>
    [HttpGet("connection-test")]
    public async Task<ActionResult<ApiResponse<object>>> TestConnection()
    {
        try
        {
            // This will test if RabbitMQ connection is working
            var connectionTest = new
            {
                Message = "Testing RabbitMQ connection...",
                Timestamp = DateTime.UtcNow,
                Action = "This endpoint tests basic RabbitMQ connectivity"
            };

            // Try to declare a test queue to verify connection
            await _producerService.InitializeTopologyAsync();
            
            return Ok(ApiResponse<object>.SuccessResponse(connectionTest, "RabbitMQ connection test successful"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "RabbitMQ connection test failed");
            return StatusCode(500, ApiResponse<object>.ErrorResponse($"RabbitMQ connection failed: {ex.Message}"));
        }
    }
}