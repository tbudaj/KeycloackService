using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using KeyCloackRabbitMQ.DemoApplication.Models;
using KeyCloackRabbitMQ.DemoApplication.Services;
using System.Security.Claims;

namespace KeyCloackRabbitMQ.DemoApplication.Controllers;

/// <summary>
/// Secured version of Messages Controller requiring JWT authentication
/// </summary>
[ApiController]
[Route("api/secure-messages")]
[Authorize] // Wymaga autoryzacji JWT dla wszystkich endpoint'ów
public class SecureMessagesController : ControllerBase
{
    private readonly MessageProducerService _producerService;
    private readonly ILogger<SecureMessagesController> _logger;

    public SecureMessagesController(MessageProducerService producerService, ILogger<SecureMessagesController> logger)
    {
        _producerService = producerService;
        _logger = logger;
    }

    /// <summary>
    /// Send a test message to the queue (requires valid JWT token)
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

            // Get user information from JWT token
            var userId = GetUserIdFromToken();
            var userName = GetUserNameFromToken();

            // Add user context to metadata
            var enrichedMetadata = request.Metadata ?? new Dictionary<string, object>();
            enrichedMetadata["authorizedUser"] = userName ?? "Unknown";
            enrichedMetadata["userId"] = userId ?? "Unknown";
            enrichedMetadata["timestamp"] = DateTime.UtcNow;
            enrichedMetadata["source"] = "SecureAPI";

            var message = await _producerService.SendTestMessageAsync(request.Content, enrichedMetadata);
            
            _logger.LogInformation("?? Secured test message sent via API by user {UserName} ({UserId}): {MessageId}", 
                userName, userId, message.Id);
            
            return Ok(ApiResponse<TestMessage>.SuccessResponse(message, 
                $"Secured test message sent successfully by {userName}"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send secured test message");
            return StatusCode(500, ApiResponse<TestMessage>.ErrorResponse($"Failed to send message: {ex.Message}"));
        }
    }

    /// <summary>
    /// Send an order to the queue (requires valid JWT token)
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

            // Add user audit information
            var userId = GetUserIdFromToken();
            var userName = GetUserNameFromToken();
            
            // Create enriched order with audit info
            var enrichedOrder = new Order
            {
                Id = order.Id,
                CustomerName = order.CustomerName,
                ProductName = order.ProductName,
                Amount = order.Amount,
                OrderDate = order.OrderDate,
                Status = order.Status
            };

            var sentOrder = await _producerService.SendOrderAsync(enrichedOrder);
            
            _logger.LogInformation("?? Secured order sent via API by user {UserName} ({UserId}): {OrderId}", 
                userName, userId, sentOrder.Id);
            
            return Ok(ApiResponse<Order>.SuccessResponse(sentOrder, 
                $"Secured order sent successfully by {userName}"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send secured order");
            return StatusCode(500, ApiResponse<Order>.ErrorResponse($"Failed to send order: {ex.Message}"));
        }
    }

    /// <summary>
    /// Send a notification (requires valid JWT token)
    /// </summary>
    [HttpPost("notification")]
    public async Task<ActionResult<ApiResponse<object>>> SendNotification([FromBody] object notification)
    {
        try
        {
            var userId = GetUserIdFromToken();
            var userName = GetUserNameFromToken();

            // Extract notification data and add user context
            var title = $"Demo Notification from {userName}";
            var body = notification?.ToString() ?? "Secured notification";
            var recipient = GetEmailFromToken() ?? "demo@example.com";

            await _producerService.SendNotificationAsync(title, body, recipient);
            
            _logger.LogInformation("?? Secured notification sent via API by user {UserName} ({UserId})", 
                userName, userId);
            
            return Ok(ApiResponse<object>.SuccessResponse(
                new { 
                    Title = title, 
                    Body = body, 
                    Recipient = recipient,
                    SentBy = userName,
                    UserId = userId
                }, 
                $"Secured notification sent successfully by {userName}"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send secured notification");
            return StatusCode(500, ApiResponse<object>.ErrorResponse($"Failed to send notification: {ex.Message}"));
        }
    }

    /// <summary>
    /// Send multiple test messages at once (requires valid JWT token)
    /// </summary>
    [HttpPost("test/bulk")]
    public async Task<ActionResult<ApiResponse<List<TestMessage>>>> SendBulkTestMessages([FromBody] List<SendMessageRequest> requests)
    {
        try
        {
            var userId = GetUserIdFromToken();
            var userName = GetUserNameFromToken();
            var messages = new List<TestMessage>();

            foreach (var request in requests)
            {
                if (!string.IsNullOrWhiteSpace(request.Content))
                {
                    // Add user context to each message
                    var enrichedMetadata = request.Metadata ?? new Dictionary<string, object>();
                    enrichedMetadata["authorizedUser"] = userName ?? "Unknown";
                    enrichedMetadata["userId"] = userId ?? "Unknown";
                    enrichedMetadata["bulkOperation"] = true;
                    enrichedMetadata["source"] = "SecureAPI-Bulk";

                    var message = await _producerService.SendTestMessageAsync(request.Content, enrichedMetadata);
                    messages.Add(message);
                }
            }

            _logger.LogInformation("?? Secured bulk messages sent via API by user {UserName} ({UserId}): {Count} messages", 
                userName, userId, messages.Count);
            
            return Ok(ApiResponse<List<TestMessage>>.SuccessResponse(messages, 
                $"{messages.Count} secured test messages sent successfully by {userName}"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send secured bulk test messages");
            return StatusCode(500, ApiResponse<List<TestMessage>>.ErrorResponse($"Failed to send bulk messages: {ex.Message}"));
        }
    }

    /// <summary>
    /// Send test message directly to queue (bypassing exchange) - requires valid JWT token
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

            var userId = GetUserIdFromToken();
            var userName = GetUserNameFromToken();

            // Create test message with user context
            var message = new TestMessage
            {
                Content = request.Content,
                From = $"SecureAPI-{userName}",
                Metadata = request.Metadata ?? new Dictionary<string, object>()
            };
            
            message.Metadata["authorizedUser"] = userName ?? "Unknown";
            message.Metadata["userId"] = userId ?? "Unknown";
            message.Metadata["directSend"] = true;

            // Send directly to queue using default exchange
            await _producerService.SendTestMessageDirectAsync(message);
            
            _logger.LogInformation("?? Secured test message sent DIRECTLY to queue by user {UserName} ({UserId}): {MessageId}", 
                userName, userId, message.Id);
            
            return Ok(ApiResponse<TestMessage>.SuccessResponse(message, 
                $"Secured test message sent directly to queue by {userName}"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send secured direct test message");
            return StatusCode(500, ApiResponse<TestMessage>.ErrorResponse($"Failed to send direct message: {ex.Message}"));
        }
    }

    /// <summary>
    /// Get user profile information from JWT token
    /// </summary>
    [HttpGet("profile")]
    public ActionResult<ApiResponse<object>> GetUserProfile()
    {
        try
        {
            var userId = GetUserIdFromToken();
            var userName = GetUserNameFromToken();
            var email = GetEmailFromToken();
            var roles = GetRolesFromToken();

            var userProfile = new
            {
                UserId = userId,
                UserName = userName,
                Email = email,
                Roles = roles,
                Claims = User.Claims.Select(c => new { c.Type, c.Value }).ToList(),
                TokenExpiry = GetTokenExpiryFromToken(),
                Issuer = GetIssuerFromToken()
            };

            _logger.LogInformation("?? User profile requested by {UserName} ({UserId})", userName, userId);

            return Ok(ApiResponse<object>.SuccessResponse(userProfile, "User profile retrieved successfully"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get user profile");
            return StatusCode(500, ApiResponse<object>.ErrorResponse($"Failed to get user profile: {ex.Message}"));
        }
    }

    /// <summary>
    /// Test endpoint to verify JWT token validity
    /// </summary>
    [HttpGet("auth-test")]
    public ActionResult<ApiResponse<object>> TestAuth()
    {
        var userName = GetUserNameFromToken();
        var userId = GetUserIdFromToken();

        return Ok(ApiResponse<object>.SuccessResponse(
            new { 
                Message = "JWT Authentication successful!",
                UserName = userName,
                UserId = userId,
                Timestamp = DateTime.UtcNow
            }, 
            "Authentication test passed"));
    }

    #region Helper Methods for JWT Token Claims

    private string? GetUserIdFromToken()
    {
        return User.FindFirst(ClaimTypes.NameIdentifier)?.Value 
               ?? User.FindFirst("sub")?.Value;
    }

    private string? GetUserNameFromToken()
    {
        return User.FindFirst(ClaimTypes.Name)?.Value 
               ?? User.FindFirst("preferred_username")?.Value 
               ?? User.FindFirst("name")?.Value;
    }

    private string? GetEmailFromToken()
    {
        return User.FindFirst(ClaimTypes.Email)?.Value 
               ?? User.FindFirst("email")?.Value;
    }

    private List<string> GetRolesFromToken()
    {
        return User.FindAll(ClaimTypes.Role)
                  .Select(c => c.Value)
                  .ToList();
    }

    private DateTime? GetTokenExpiryFromToken()
    {
        var expClaim = User.FindFirst("exp")?.Value;
        if (long.TryParse(expClaim, out var exp))
        {
            return DateTimeOffset.FromUnixTimeSeconds(exp).DateTime;
        }
        return null;
    }

    private string? GetIssuerFromToken()
    {
        return User.FindFirst("iss")?.Value;
    }

    #endregion
}