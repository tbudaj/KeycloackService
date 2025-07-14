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
        _logger.LogInformation("Message Consumer Service started");

        try
        {
            // Start consuming different types of messages
            await StartConsumingAsync(stoppingToken);

            // Keep the service running
            await Task.Delay(Timeout.Infinite, stoppingToken);
        }
        catch (OperationCanceledException)
        {
            _logger.LogInformation("Message Consumer Service is stopping due to cancellation");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in Message Consumer Service");
        }
    }

    private async Task StartConsumingAsync(CancellationToken cancellationToken)
    {
        // Consume test messages
        var testMessagesTag = await _rabbitService.ConsumeAsync<TestMessage>(
            queueName: "demo.messages",
            onMessage: ProcessTestMessageAsync,
            autoAck: false,
            cancellationToken: cancellationToken);
        
        _consumerTags.Add(testMessagesTag);
        _logger.LogInformation("Started consuming test messages with tag: {ConsumerTag}", testMessagesTag);

        // Consume orders
        var ordersTag = await _rabbitService.ConsumeAsync<Order>(
            queueName: "demo.orders",
            onMessage: ProcessOrderAsync,
            autoAck: false,
            cancellationToken: cancellationToken);
        
        _consumerTags.Add(ordersTag);
        _logger.LogInformation("Started consuming orders with tag: {ConsumerTag}", ordersTag);

        // Consume notifications
        var notificationsTag = await _rabbitService.ConsumeStringAsync(
            queueName: "demo.notifications",
            onMessage: ProcessNotificationAsync,
            autoAck: false,
            cancellationToken: cancellationToken);
        
        _consumerTags.Add(notificationsTag);
        _logger.LogInformation("Started consuming notifications with tag: {ConsumerTag}", notificationsTag);
    }

    private async Task<bool> ProcessTestMessageAsync(TestMessage message)
    {
        try
        {
            _logger.LogInformation("?? OTRZYMANO WIADOMOŒÆ TESTOW¥:");
            _logger.LogInformation("   ID: {MessageId}", message.Id);
            _logger.LogInformation("   Treœæ: {Content}", message.Content);
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

            _logger.LogInformation("? Wiadomoœæ testowa {MessageId} przetworzona pomyœlnie", message.Id);
            return true; // ACK
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "? B³¹d przetwarzania wiadomoœci testowej {MessageId}", message.Id);
            return false; // NACK
        }
    }

    private async Task<bool> ProcessOrderAsync(Order order)
    {
        try
        {
            _logger.LogInformation("?? OTRZYMANO ZAMÓWIENIE:");
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
            _logger.LogInformation("?? Zamówienie {OrderId} przesz³o do statusu: {Status}", order.Id, order.Status);

            await Task.Delay(100);

            order.Status = OrderStatus.Shipped;
            _logger.LogInformation("?? Zamówienie {OrderId} zosta³o wys³ane", order.Id);

            _logger.LogInformation("? Zamówienie {OrderId} przetworzone pomyœlnie", order.Id);
            return true; // ACK
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "? B³¹d przetwarzania zamówienia {OrderId}", order.Id);
            return false; // NACK
        }
    }

    private async Task<bool> ProcessNotificationAsync(string notificationJson)
    {
        try
        {
            _logger.LogInformation("?? OTRZYMANO POWIADOMIENIE:");
            _logger.LogInformation("   Raw JSON: {NotificationJson}", notificationJson);

            // Simulate notification processing
            await Task.Delay(50);

            _logger.LogInformation("? Powiadomienie przetworzone pomyœlnie");
            return true; // ACK
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "? B³¹d przetwarzania powiadomienia");
            return false; // NACK
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Stopping Message Consumer Service...");

        // Cancel all consumers
        foreach (var consumerTag in _consumerTags)
        {
            try
            {
                await _rabbitService.CancelConsumerAsync(consumerTag, cancellationToken);
                _logger.LogInformation("Cancelled consumer: {ConsumerTag}", consumerTag);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to cancel consumer: {ConsumerTag}", consumerTag);
            }
        }

        await base.StopAsync(cancellationToken);
        _logger.LogInformation("Message Consumer Service stopped");
    }
}