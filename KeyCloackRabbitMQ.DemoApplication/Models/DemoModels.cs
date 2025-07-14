namespace KeyCloackRabbitMQ.DemoApplication.Models;

/// <summary>
/// Test message model for demonstration purposes
/// </summary>
public class TestMessage
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Content { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string From { get; set; } = "DemoApplication";
    public Dictionary<string, object> Metadata { get; set; } = new();
}

/// <summary>
/// Order model for demonstration purposes
/// </summary>
public class Order
{
    public int Id { get; set; }
    public string CustomerName { get; set; } = string.Empty;
    public decimal Amount { get; set; }
    public string ProductName { get; set; } = string.Empty;
    public DateTime OrderDate { get; set; } = DateTime.UtcNow;
    public OrderStatus Status { get; set; } = OrderStatus.Created;
}

/// <summary>
/// Order status enumeration
/// </summary>
public enum OrderStatus
{
    Created,
    Processing,
    Shipped,
    Delivered,
    Cancelled
}

/// <summary>
/// Health check response model
/// </summary>
public class HealthStatus
{
    public string Service { get; set; } = string.Empty;
    public bool IsHealthy { get; set; }
    public string Status { get; set; } = string.Empty;
    public string? Details { get; set; }
    public DateTime CheckedAt { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// API response wrapper
/// </summary>
public class ApiResponse<T>
{
    public bool Success { get; set; }
    public T? Data { get; set; }
    public string? Message { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    public static ApiResponse<T> SuccessResponse(T data, string? message = null)
    {
        return new ApiResponse<T>
        {
            Success = true,
            Data = data,
            Message = message
        };
    }

    public static ApiResponse<T> ErrorResponse(string message)
    {
        return new ApiResponse<T>
        {
            Success = false,
            Message = message
        };
    }
}

/// <summary>
/// Send message request
/// </summary>
public class SendMessageRequest
{
    public string Content { get; set; } = string.Empty;
    public string? QueueName { get; set; }
    public Dictionary<string, object> Metadata { get; set; } = new();
}