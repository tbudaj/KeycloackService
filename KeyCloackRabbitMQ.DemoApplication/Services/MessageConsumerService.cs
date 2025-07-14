using KeyCloackService.RabbitMQ;
using KeyCloackRabbitMQ.DemoApplication.Models;

namespace KeyCloackRabbitMQ.DemoApplication.Services;

/// <summary>
/// Background service for consuming messages from RabbitMQ queues
/// </summary>
public class MessageConsumerService : BackgroundService
{
    private readonly KeycloakRabbitMQService _rabbitService;
    private readonly ILogger<MessageConsumerService> _logger;
    private readonly List<string> _consumerTags = new();

    public MessageConsumerService(KeycloakRabbitMQService rabbitService, ILogger<MessageConsumerService> logger)
    {
        _rabbitService = rabbitService;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("🚀 Message Consumer Service starting...");

        try
        {
            // Start consuming different types of messages
            await StartConsumingAsync(stoppingToken);

            _logger.LogInformation("⏳ Message Consumer Service is now listening for messages. Consumers are active!");
            
            // Keep the service running indefinitely
            await Task.Delay(Timeout.Infinite, stoppingToken);
        }
        catch (OperationCanceledException)
        {
            _logger.LogInformation("⏹️ Message Consumer Service is stopping due to cancellation");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "💥 Error in Message Consumer Service");
            
            // Wait a bit before potentially restarting
            try
            {
                await Task.Delay(5000, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                // Expected when stopping
            }
            
            throw; // Re-throw to potentially trigger service restart
        }
        finally
        {
            _logger.LogInformation("🔚 Message Consumer Service ExecuteAsync completed");
        }
    }

    private async Task StartConsumingAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("🚀 Starting message consumers setup...");

        try
        {
            // Ensure topology exists first
            _logger.LogInformation("📦 Setting up RabbitMQ topology...");
            
            // Declare main exchange
            await _rabbitService.DeclareExchangeAsync("demo.events", "topic", durable: true, cancellationToken: cancellationToken);
            _logger.LogInformation("✅ Exchange 'demo.events' declared");
            
            // Declare queues
            await _rabbitService.DeclareQueueAsync("demo.messages", durable: true, cancellationToken: cancellationToken);
            _logger.LogInformation("✅ Queue 'demo.messages' declared");
            
            await _rabbitService.DeclareQueueAsync("demo.orders", durable: true, cancellationToken: cancellationToken);
            _logger.LogInformation("✅ Queue 'demo.orders' declared");
            
            await _rabbitService.DeclareQueueAsync("demo.notifications", durable: true, cancellationToken: cancellationToken);
            _logger.LogInformation("✅ Queue 'demo.notifications' declared");
            
            // Bind queues to exchange
            await _rabbitService.BindQueueAsync("demo.messages", "demo.events", "message.*", cancellationToken: cancellationToken);
            _logger.LogInformation("✅ Queue 'demo.messages' bound to exchange 'demo.events' with pattern 'message.*'");
            
            await _rabbitService.BindQueueAsync("demo.orders", "demo.events", "order.*", cancellationToken: cancellationToken);
            _logger.LogInformation("✅ Queue 'demo.orders' bound to exchange 'demo.events' with pattern 'order.*'");
            
            await _rabbitService.BindQueueAsync("demo.notifications", "demo.events", "notification.*", cancellationToken: cancellationToken);
            _logger.LogInformation("✅ Queue 'demo.notifications' bound to exchange 'demo.events' with pattern 'notification.*'");

            // Now start consuming
            _logger.LogInformation("🔧 Setting up consumers...");

            // Consume test messages
            _logger.LogInformation("🔧 Setting up test messages consumer...");
            var testMessagesTag = await _rabbitService.ConsumeAsync<TestMessage>(
                queueName: "demo.messages",
                onMessage: ProcessTestMessageAsync,
                autoAck: false,
                cancellationToken: cancellationToken);
            
            _consumerTags.Add(testMessagesTag);
            _logger.LogInformation("✅ Started consuming test messages with tag: {ConsumerTag}", testMessagesTag);

            // Consume orders
            _logger.LogInformation("🔧 Setting up orders consumer...");
            var ordersTag = await _rabbitService.ConsumeAsync<Order>(
                queueName: "demo.orders",
                onMessage: ProcessOrderAsync,
                autoAck: false,
                cancellationToken: cancellationToken);
            
            _consumerTags.Add(ordersTag);
            _logger.LogInformation("✅ Started consuming orders with tag: {ConsumerTag}", ordersTag);

            // Consume notifications
            _logger.LogInformation("🔧 Setting up notifications consumer...");
            var notificationsTag = await _rabbitService.ConsumeStringAsync(
                queueName: "demo.notifications",
                onMessage: ProcessNotificationAsync,
                autoAck: false,
                cancellationToken: cancellationToken);
            
            _consumerTags.Add(notificationsTag);
            _logger.LogInformation("✅ Started consuming notifications with tag: {ConsumerTag}", notificationsTag);

            _logger.LogInformation("🎉 All consumers setup completed successfully! Ready to process messages...");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "💥 Failed to setup consumers");
            throw;
        }
    }

    private async Task<bool> ProcessTestMessageAsync(TestMessage message)
    {
        try
        {
            _logger.LogInformation("🔥 OTRZYMANO WIADOMOŚĆ TESTOWĄ:");
            _logger.LogInformation("   ID: {MessageId}", message.Id);
            _logger.LogInformation("   Treść: {Content}", message.Content);
            _logger.LogInformation("   Od: {From}", message.From);
            _logger.LogInformation("   Timestamp: {Timestamp}", message.Timestamp);
            
            if (message.Metadata.Any())
            {
                _logger.LogInformation("   Metadata:");
                foreach (var kvp in message.Metadata)
                {
                    _logger.LogInformation("     {Key}: {Value}", kvp.Key, kvp.Value);
                }
            }

            // Simulate processing time
            await Task.Delay(100);

            _logger.LogInformation("✅ Wiadomość testowa {MessageId} przetworzona pomyślnie", message.Id);
            return true; // ACK
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Błąd przetwarzania wiadomości testowej {MessageId}", message.Id);
            return false; // NACK
        }
    }

    private async Task<bool> ProcessOrderAsync(Order order)
    {
        try
        {
            _logger.LogInformation("📦 OTRZYMANO ZAMÓWIENIE:");
            _logger.LogInformation("   ID: {OrderId}", order.Id);
            _logger.LogInformation("   Klient: {CustomerName}", order.CustomerName);
            _logger.LogInformation("   Produkt: {ProductName}", order.ProductName);
            _logger.LogInformation("   Kwota: {Amount:C}", order.Amount);
            _logger.LogInformation("   Data: {OrderDate}", order.OrderDate);
            _logger.LogInformation("   Status: {Status}", order.Status);

            // Simulate order processing
            await Task.Delay(200);

            // Update order status
            order.Status = OrderStatus.Processing;
            _logger.LogInformation("🔄 Zamówienie {OrderId} przeszło do statusu: {Status}", order.Id, order.Status);

            await Task.Delay(100);

            order.Status = OrderStatus.Shipped;
            _logger.LogInformation("🚚 Zamówienie {OrderId} zostało wysłane", order.Id);

            _logger.LogInformation("✅ Zamówienie {OrderId} przetworzone pomyślnie", order.Id);
            return true; // ACK
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Błąd przetwarzania zamówienia {OrderId}", order.Id);
            return false; // NACK
        }
    }

    private async Task<bool> ProcessNotificationAsync(string notificationJson)
    {
        try
        {
            _logger.LogInformation("🔔 OTRZYMANO POWIADOMIENIE:");
            _logger.LogInformation("   Raw JSON: {NotificationJson}", notificationJson);

            // Simulate notification processing
            await Task.Delay(50);

            _logger.LogInformation("✅ Powiadomienie przetworzone pomyślnie");
            return true; // ACK
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Błąd przetwarzania powiadomienia");
            return false; // NACK
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("🛑 Stopping Message Consumer Service...");

        // Cancel all consumers
        foreach (var consumerTag in _consumerTags)
        {
            try
            {
                await _rabbitService.CancelConsumerAsync(consumerTag, cancellationToken);
                _logger.LogInformation("✅ Cancelled consumer: {ConsumerTag}", consumerTag);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "⚠️ Failed to cancel consumer: {ConsumerTag}", consumerTag);
            }
        }

        await base.StopAsync(cancellationToken);
        _logger.LogInformation("✅ Message Consumer Service stopped");
    }
}