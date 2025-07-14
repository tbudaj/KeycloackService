using RabbitMQ.Client;
using RabbitMQ.Client.Events;
using KeyCloackService.Models;
using Microsoft.Extensions.Logging;
using System.Text;
using System.Text.Json;

namespace KeyCloackService.RabbitMQ;

/// <summary>
/// High-level service for RabbitMQ operations with Keycloak authentication
/// </summary>
public class KeycloakRabbitMQService : IDisposable
{
    private readonly KeycloakRabbitMQConnectionFactory _connectionFactory;
    private readonly ILogger<KeycloakRabbitMQService>? _logger;
    private readonly SemaphoreSlim _channelSemaphore = new(1, 1);
    
    private IModel? _channel;
    private bool _disposed = false;

    public KeycloakRabbitMQService(
        KeycloakRabbitMQConnectionFactory connectionFactory,
        ILogger<KeycloakRabbitMQService>? logger = null)
    {
        _connectionFactory = connectionFactory ?? throw new ArgumentNullException(nameof(connectionFactory));
        _logger = logger;
    }

    /// <summary>
    /// Publishes a message to the specified exchange and routing key
    /// </summary>
    /// <typeparam name="T">Type of the message</typeparam>
    /// <param name="exchange">Exchange name</param>
    /// <param name="routingKey">Routing key</param>
    /// <param name="message">Message to publish</param>
    /// <param name="properties">Additional message properties</param>
    /// <param name="cancellationToken">Cancellation token</param>
    public async Task PublishAsync<T>(
        string exchange,
        string routingKey,
        T message,
        IBasicProperties? properties = null,
        CancellationToken cancellationToken = default)
    {
        var channel = await GetChannelAsync(cancellationToken);
        
        var messageBody = JsonSerializer.SerializeToUtf8Bytes(message);
        var messageProperties = properties ?? channel.CreateBasicProperties();
        
        // Set default properties
        messageProperties.ContentType = "application/json";
        messageProperties.DeliveryMode = 2; // Persistent
        messageProperties.Timestamp = new AmqpTimestamp(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        
        channel.BasicPublish(
            exchange: exchange,
            routingKey: routingKey,
            basicProperties: messageProperties,
            body: messageBody);

        _logger?.LogDebug("Published message to exchange '{Exchange}' with routing key '{RoutingKey}'", 
            exchange, routingKey);
    }

    /// <summary>
    /// Publishes a string message to the specified exchange and routing key
    /// </summary>
    /// <param name="exchange">Exchange name</param>
    /// <param name="routingKey">Routing key</param>
    /// <param name="message">String message to publish</param>
    /// <param name="properties">Additional message properties</param>
    /// <param name="cancellationToken">Cancellation token</param>
    public async Task PublishStringAsync(
        string exchange,
        string routingKey,
        string message,
        IBasicProperties? properties = null,
        CancellationToken cancellationToken = default)
    {
        var channel = await GetChannelAsync(cancellationToken);
        
        var messageBody = Encoding.UTF8.GetBytes(message);
        var messageProperties = properties ?? channel.CreateBasicProperties();
        
        // Set default properties
        messageProperties.ContentType = "text/plain";
        messageProperties.DeliveryMode = 2; // Persistent
        messageProperties.Timestamp = new AmqpTimestamp(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        
        channel.BasicPublish(
            exchange: exchange,
            routingKey: routingKey,
            basicProperties: messageProperties,
            body: messageBody);

        _logger?.LogDebug("Published string message to exchange '{Exchange}' with routing key '{RoutingKey}'", 
            exchange, routingKey);
    }

    /// <summary>
    /// Declares a queue with the specified parameters
    /// </summary>
    /// <param name="queueName">Queue name</param>
    /// <param name="durable">Whether the queue should survive server restarts</param>
    /// <param name="exclusive">Whether the queue should be exclusive to this connection</param>
    /// <param name="autoDelete">Whether the queue should be deleted when no longer in use</param>
    /// <param name="arguments">Additional queue arguments</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Queue declaration result</returns>
    public async Task<QueueDeclareOk> DeclareQueueAsync(
        string queueName,
        bool durable = true,
        bool exclusive = false,
        bool autoDelete = false,
        IDictionary<string, object>? arguments = null,
        CancellationToken cancellationToken = default)
    {
        var channel = await GetChannelAsync(cancellationToken);
        
        var result = channel.QueueDeclare(
            queue: queueName,
            durable: durable,
            exclusive: exclusive,
            autoDelete: autoDelete,
            arguments: arguments);

        _logger?.LogDebug("Declared queue '{QueueName}' (durable: {Durable}, exclusive: {Exclusive}, autoDelete: {AutoDelete})", 
            queueName, durable, exclusive, autoDelete);

        return result;
    }

    /// <summary>
    /// Declares an exchange with the specified parameters
    /// </summary>
    /// <param name="exchangeName">Exchange name</param>
    /// <param name="exchangeType">Exchange type (direct, topic, fanout, headers)</param>
    /// <param name="durable">Whether the exchange should survive server restarts</param>
    /// <param name="autoDelete">Whether the exchange should be deleted when no longer in use</param>
    /// <param name="arguments">Additional exchange arguments</param>
    /// <param name="cancellationToken">Cancellation token</param>
    public async Task DeclareExchangeAsync(
        string exchangeName,
        string exchangeType = "direct",
        bool durable = true,
        bool autoDelete = false,
        IDictionary<string, object>? arguments = null,
        CancellationToken cancellationToken = default)
    {
        var channel = await GetChannelAsync(cancellationToken);
        
        channel.ExchangeDeclare(
            exchange: exchangeName,
            type: exchangeType,
            durable: durable,
            autoDelete: autoDelete,
            arguments: arguments);

        _logger?.LogDebug("Declared exchange '{ExchangeName}' of type '{ExchangeType}' (durable: {Durable}, autoDelete: {AutoDelete})", 
            exchangeName, exchangeType, durable, autoDelete);
    }

    /// <summary>
    /// Binds a queue to an exchange with the specified routing key
    /// </summary>
    /// <param name="queueName">Queue name</param>
    /// <param name="exchangeName">Exchange name</param>
    /// <param name="routingKey">Routing key</param>
    /// <param name="arguments">Additional binding arguments</param>
    /// <param name="cancellationToken">Cancellation token</param>
    public async Task BindQueueAsync(
        string queueName,
        string exchangeName,
        string routingKey,
        IDictionary<string, object>? arguments = null,
        CancellationToken cancellationToken = default)
    {
        var channel = await GetChannelAsync(cancellationToken);
        
        channel.QueueBind(
            queue: queueName,
            exchange: exchangeName,
            routingKey: routingKey,
            arguments: arguments);

        _logger?.LogDebug("Bound queue '{QueueName}' to exchange '{ExchangeName}' with routing key '{RoutingKey}'", 
            queueName, exchangeName, routingKey);
    }

    /// <summary>
    /// Sets up a consumer for the specified queue
    /// </summary>
    /// <typeparam name="T">Type of the expected message</typeparam>
    /// <param name="queueName">Queue name</param>
    /// <param name="onMessage">Message handler function</param>
    /// <param name="autoAck">Whether to automatically acknowledge messages</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Consumer tag</returns>
    public async Task<string> ConsumeAsync<T>(
        string queueName,
        Func<T, Task<bool>> onMessage,
        bool autoAck = false,
        CancellationToken cancellationToken = default)
    {
        var channel = await GetChannelAsync(cancellationToken);
        
        // Use EventingBasicConsumer instead of AsyncEventingBasicConsumer
        var consumer = new EventingBasicConsumer(channel);
        
        _logger?.LogInformation("?? Setting up consumer for queue '{QueueName}' with autoAck: {AutoAck}", queueName, autoAck);
        
        consumer.Received += (model, ea) =>
        {
            var deliveryTag = ea.DeliveryTag;
            _logger?.LogInformation("?? Message received from queue '{QueueName}', delivery tag: {DeliveryTag}", queueName, deliveryTag);
            
            // Process message in background task to avoid blocking
            Task.Run(async () =>
            {
                try
                {
                    var body = ea.Body.ToArray();
                    _logger?.LogInformation("?? Message body length: {BodyLength} bytes", body.Length);
                    
                    var bodyString = Encoding.UTF8.GetString(body);
                    _logger?.LogInformation("?? Raw message content: {MessageContent}", bodyString);
                    
                    _logger?.LogInformation("?? Starting JSON deserialization to type {MessageType}...", typeof(T).Name);
                    var message = JsonSerializer.Deserialize<T>(body);
                    _logger?.LogInformation("? Successfully deserialized message of type {MessageType}", typeof(T).Name);
                    
                    if (message != null)
                    {
                        _logger?.LogInformation("?? Calling message handler for queue '{QueueName}'...", queueName);
                        
                        var success = await onMessage(message);
                        
                        _logger?.LogInformation("? Message handler completed with result: {Success} for delivery tag: {DeliveryTag}", success, deliveryTag);
                        
                        if (!autoAck)
                        {
                            if (success)
                            {
                                channel.BasicAck(deliveryTag: deliveryTag, multiple: false);
                                _logger?.LogInformation("? Message ACK sent for delivery tag: {DeliveryTag}", deliveryTag);
                            }
                            else
                            {
                                channel.BasicNack(deliveryTag: deliveryTag, multiple: false, requeue: true);
                                _logger?.LogInformation("? Message NACK sent (requeued) for delivery tag: {DeliveryTag}", deliveryTag);
                            }
                        }
                    }
                    else
                    {
                        _logger?.LogWarning("?? Deserialized message is null for queue '{QueueName}', delivery tag: {DeliveryTag}", queueName, deliveryTag);
                        if (!autoAck)
                        {
                            channel.BasicNack(deliveryTag: deliveryTag, multiple: false, requeue: false);
                            _logger?.LogInformation("? Message NACK sent (not requeued) for null message, delivery tag: {DeliveryTag}", deliveryTag);
                        }
                    }
                }
                catch (JsonException jsonEx)
                {
                    _logger?.LogError(jsonEx, "?? JSON deserialization error for message from queue '{QueueName}', delivery tag: {DeliveryTag}. Raw content: {RawContent}", 
                        queueName, deliveryTag, Encoding.UTF8.GetString(ea.Body.ToArray()));
                    
                    if (!autoAck)
                    {
                        channel.BasicNack(deliveryTag: deliveryTag, multiple: false, requeue: false);
                        _logger?.LogInformation("? Message NACK sent (not requeued) for JSON error, delivery tag: {DeliveryTag}", deliveryTag);
                    }
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "?? Unexpected error processing message from queue '{QueueName}', delivery tag: {DeliveryTag}", queueName, deliveryTag);
                    
                    if (!autoAck)
                    {
                        channel.BasicNack(deliveryTag: deliveryTag, multiple: false, requeue: false);
                        _logger?.LogInformation("? Message NACK sent (not requeued) for unexpected error, delivery tag: {DeliveryTag}", deliveryTag);
                    }
                }
            });
        };

        var consumerTag = channel.BasicConsume(
            queue: queueName,
            autoAck: autoAck,
            consumer: consumer);

        _logger?.LogInformation("?? Started consuming messages from queue '{QueueName}' with consumer tag '{ConsumerTag}' (autoAck: {AutoAck})", 
            queueName, consumerTag, autoAck);

        return consumerTag;
    }

    /// <summary>
    /// Sets up a string consumer for the specified queue
    /// </summary>
    /// <param name="queueName">Queue name</param>
    /// <param name="onMessage">Message handler function</param>
    /// <param name="autoAck">Whether to automatically acknowledge messages</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Consumer tag</returns>
    public async Task<string> ConsumeStringAsync(
        string queueName,
        Func<string, Task<bool>> onMessage,
        bool autoAck = false,
        CancellationToken cancellationToken = default)
    {
        var channel = await GetChannelAsync(cancellationToken);
        
        var consumer = new AsyncEventingBasicConsumer(channel);
        
        consumer.Received += async (model, ea) =>
        {
            try
            {
                var body = ea.Body.ToArray();
                var message = Encoding.UTF8.GetString(body);
                
                var success = await onMessage(message);
                
                if (!autoAck)
                {
                    if (success)
                    {
                        channel.BasicAck(deliveryTag: ea.DeliveryTag, multiple: false);
                    }
                    else
                    {
                        channel.BasicNack(deliveryTag: ea.DeliveryTag, multiple: false, requeue: true);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Error processing string message from queue '{QueueName}'", queueName);
                
                if (!autoAck)
                {
                    channel.BasicNack(deliveryTag: ea.DeliveryTag, multiple: false, requeue: false);
                }
            }
        };

        var consumerTag = channel.BasicConsume(
            queue: queueName,
            autoAck: autoAck,
            consumer: consumer);

        _logger?.LogInformation("Started consuming string messages from queue '{QueueName}' with consumer tag '{ConsumerTag}'", 
            queueName, consumerTag);

        return consumerTag;
    }

    /// <summary>
    /// Cancels a consumer
    /// </summary>
    /// <param name="consumerTag">Consumer tag to cancel</param>
    /// <param name="cancellationToken">Cancellation token</param>
    public async Task CancelConsumerAsync(string consumerTag, CancellationToken cancellationToken = default)
    {
        var channel = await GetChannelAsync(cancellationToken);
        channel.BasicCancel(consumerTag);
        
        _logger?.LogInformation("Cancelled consumer with tag '{ConsumerTag}'", consumerTag);
    }

    private async Task<IModel> GetChannelAsync(CancellationToken cancellationToken)
    {
        await _channelSemaphore.WaitAsync(cancellationToken);
        try
        {
            if (_channel?.IsOpen == true)
            {
                return _channel;
            }

            _channel?.Dispose();
            _channel = await _connectionFactory.CreateChannelAsync(cancellationToken);
            
            return _channel;
        }
        finally
        {
            _channelSemaphore.Release();
        }
    }

    public void Dispose()
    {
        if (_disposed) return;

        try
        {
            _channel?.Close();
            _channel?.Dispose();
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Error disposing RabbitMQ channel");
        }

        _connectionFactory?.Dispose();
        _channelSemaphore.Dispose();
        _disposed = true;
    }
}