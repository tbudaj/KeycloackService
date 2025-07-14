using KeyCloackService.RabbitMQ;
using KeyCloackRabbitMQ.DemoApplication.Models;

namespace KeyCloackRabbitMQ.DemoApplication.Services;

/// <summary>
/// Service for producing messages to RabbitMQ queues
/// </summary>
public class MessageProducerService
{
    private readonly KeycloakRabbitMQService _rabbitService;
    private readonly ILogger<MessageProducerService> _logger;

    public MessageProducerService(KeycloakRabbitMQService rabbitService, ILogger<MessageProducerService> logger)
    {
        _rabbitService = rabbitService;
        _logger = logger;
    }

    /// <summary>
    /// Initialize RabbitMQ topology (exchanges, queues, bindings)
    /// </summary>
    public async Task InitializeTopologyAsync()
    {
        try
        {
            // Declare main exchange
            await _rabbitService.DeclareExchangeAsync("demo.events", "topic", durable: true);
            
            // Declare queues
            await _rabbitService.DeclareQueueAsync("demo.messages", durable: true);
            await _rabbitService.DeclareQueueAsync("demo.orders", durable: true);
            await _rabbitService.DeclareQueueAsync("demo.notifications", durable: true);
            
            // Bind queues to exchange
            await _rabbitService.BindQueueAsync("demo.messages", "demo.events", "message.*");
            await _rabbitService.BindQueueAsync("demo.orders", "demo.events", "order.*");
            await _rabbitService.BindQueueAsync("demo.notifications", "demo.events", "notification.*");

            _logger.LogInformation("RabbitMQ topology initialized successfully");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to initialize RabbitMQ topology");
            throw;
        }
    }

    /// <summary>
    /// Send a test message to the demo.messages queue
    /// </summary>
    public async Task<TestMessage> SendTestMessageAsync(string content, Dictionary<string, object>? metadata = null)
    {
        var message = new TestMessage
        {
            Content = content,
            Metadata = metadata ?? new Dictionary<string, object>()
        };

        await _rabbitService.PublishAsync(
            exchange: "demo.events",
            routingKey: "message.test",
            message: message);

        _logger.LogInformation("Test message sent: {MessageId} - {Content}", message.Id, message.Content);
        return message;
    }

    /// <summary>
    /// Send an order to the demo.orders queue
    /// </summary>
    public async Task<Order> SendOrderAsync(Order order)
    {
        await _rabbitService.PublishAsync(
            exchange: "demo.events",
            routingKey: "order.created",
            message: order);

        _logger.LogInformation("Order sent: {OrderId} - {CustomerName}", order.Id, order.CustomerName);
        return order;
    }

    /// <summary>
    /// Send a notification
    /// </summary>
    public async Task SendNotificationAsync(string title, string body, string recipient)
    {
        var notification = new
        {
            Id = Guid.NewGuid(),
            Title = title,
            Body = body,
            Recipient = recipient,
            Timestamp = DateTime.UtcNow
        };

        await _rabbitService.PublishAsync(
            exchange: "demo.events",
            routingKey: "notification.info",
            message: notification);

        _logger.LogInformation("Notification sent: {Title} to {Recipient}", title, recipient);
    }

    /// <summary>
    /// Send a test message directly to queue (bypassing exchange) for debugging
    /// </summary>
    public async Task SendTestMessageDirectAsync(TestMessage message)
    {
        // Ensure queue exists
        await _rabbitService.DeclareQueueAsync("demo.messages", durable: true);

        // Send directly to queue using default exchange (empty string)
        await _rabbitService.PublishAsync(
            exchange: "",  // Default exchange - routes directly to queue
            routingKey: "demo.messages",  // Queue name as routing key
            message: message);

        _logger.LogInformation("?? Test message sent DIRECTLY to queue: {MessageId} - {Content}", message.Id, message.Content);
    }
}