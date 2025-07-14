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
}