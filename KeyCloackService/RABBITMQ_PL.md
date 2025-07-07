# KeycloakService - Integracja z RabbitMQ

Kompletny przewodnik po integracji KeycloakService z RabbitMQ dla autoryzacji kolejek wiadomoœci.

## Funkcjonalnoœci RabbitMQ

- **Autoryzacja JWT** - u¿ywa tokenów Keycloak do autoryzacji RabbitMQ
- **Automatyczne odœwie¿anie po³¹czeñ** - podczas odœwie¿ania tokenów
- **Thread-safe operations** - bezpieczne operacje wielow¹tkowe
- **Asynchroniczne API** - wszystkie operacje async/await
- **Publikowanie i konsumowanie** - kompletne API dla wiadomoœci
- **Zarz¹dzanie topologi¹** - queues, exchanges, bindings
- **Dependency Injection** - pe³na integracja z ASP.NET Core

## Wymagania

- **RabbitMQ Server** z w³¹czonym pluginem JWT Authentication
- **Keycloak Server** z poprawnie skonfigurowanym klientem
- **.NET 8** lub nowszy

## Instalacja

### Package Manager
```powershell
Install-Package KeycloakService
Install-Package RabbitMQ.Client
```

### .NET CLI
```bash
dotnet add package KeycloakService
dotnet add package RabbitMQ.Client
```

## Konfiguracja RabbitMQ

### W³¹czenie JWT Authentication w RabbitMQ

1. **W³¹cz plugin JWT**:
```bash
rabbitmq-plugins enable rabbitmq_auth_backend_oauth2
```

2. **Konfiguruj RabbitMQ** (`rabbitmq.conf`):
```ini
# OAuth2/JWT Configuration
auth_backends.1 = oauth2
auth_oauth2.resource_server_id = rabbitmq
auth_oauth2.jwks_url = https://your-keycloak-server.com/realms/your-realm/protocol/openid-connect/certs
auth_oauth2.issuer = https://your-keycloak-server.com/realms/your-realm
auth_oauth2.verify_aud = false
auth_oauth2.scope_prefix = rabbitmq.
```

3. **Restart RabbitMQ**:
```bash
sudo systemctl restart rabbitmq-server
```

### Konfiguracja Keycloak

1. **Utwórz klienta RabbitMQ** w Keycloak Admin Console
2. **Skonfiguruj uprawnienia** (scopes/roles) dla kolejek RabbitMQ
3. **Dodaj mappers** do tokenów (np. audience mapper)

## Podstawowe u¿ycie

### 1. Konfiguracja appsettings.json

```json
{
  "Keycloak": {
    "ServerUrl": "https://your-keycloak-server.com",
    "Realm": "your-realm",
    "ClientId": "rabbitmq-client",
    "ClientSecret": "your-client-secret",
    "Flow": "ClientCredentials"
  },
  "RabbitMQ": {
    "HostName": "localhost",
    "Port": 5672,
    "VirtualHost": "/",
    "UseKeycloakAuthentication": true,
    "UseSsl": false,
    "AutomaticRecoveryEnabled": true
  }
}
```

### 2. Konfiguracja w Program.cs

```csharp
using KeyCloackService.Extensions;

var builder = WebApplication.CreateBuilder(args);

// Dodaj KeycloakService z obs³ug¹ RabbitMQ
builder.Services.AddKeycloakRabbitMQ();

// Lub z custom konfiguracj¹
builder.Services.AddKeycloakRabbitMQ(
    keycloak => {
        keycloak.ServerUrl = "https://keycloak.example.com";
        keycloak.Realm = "production";
        keycloak.ClientId = "rabbitmq-service";
        keycloak.ClientSecret = Environment.GetEnvironmentVariable("KEYCLOAK_SECRET");
        keycloak.Flow = AuthenticationFlow.ClientCredentials;
    },
    rabbitmq => {
        rabbitmq.HostName = "rabbitmq.production.com";
        rabbitmq.Port = 5671;
        rabbitmq.UseSsl = true;
        rabbitmq.UseKeycloakAuthentication = true;
    });

var app = builder.Build();
```

### 3. Publikowanie wiadomoœci

```csharp
public class MessagePublisher
{
    private readonly KeycloakRabbitMQService _rabbitService;

    public MessagePublisher(KeycloakRabbitMQService rabbitService)
    {
        _rabbitService = rabbitService;
    }

    public async Task PublishOrderAsync(Order order)
    {
        // Zadeklaruj exchange i queue
        await _rabbitService.DeclareExchangeAsync("orders", "topic");
        await _rabbitService.DeclareQueueAsync("order.created");
        await _rabbitService.BindQueueAsync("order.created", "orders", "order.created");

        // Publikuj wiadomoœæ
        await _rabbitService.PublishAsync(
            exchange: "orders",
            routingKey: "order.created", 
            message: order);
    }
}
```

### 4. Konsumowanie wiadomoœci

```csharp
public class OrderProcessor : BackgroundService
{
    private readonly KeycloakRabbitMQService _rabbitService;
    private readonly ILogger<OrderProcessor> _logger;

    public OrderProcessor(
        KeycloakRabbitMQService rabbitService, 
        ILogger<OrderProcessor> logger)
    {
        _rabbitService = rabbitService;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Deklaruj infrastrukturê
        await _rabbitService.DeclareQueueAsync("order.created");

        // Zacznij konsumowaæ
        await _rabbitService.ConsumeAsync<Order>(
            queueName: "order.created",
            onMessage: ProcessOrderAsync,
            autoAck: false,
            cancellationToken: stoppingToken);

        // Utrzymuj serwis dzia³aj¹cy
        await Task.Delay(Timeout.Infinite, stoppingToken);
    }

    private async Task<bool> ProcessOrderAsync(Order order)
    {
        try
        {
            _logger.LogInformation("Przetwarzam zamówienie {OrderId}", order.Id);
            
            // Przetwórz zamówienie
            await ProcessBusinessLogic(order);
            
            _logger.LogInformation("Zamówienie {OrderId} przetworzone pomyœlnie", order.Id);
            return true; // ACK
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "B³¹d przetwarzania zamówienia {OrderId}", order.Id);
            return false; // NACK - wiadomoœæ zostanie ponownie przetworzona
        }
    }
}
```

## Zaawansowane scenariusze

### Mikroservice z wieloma kolejkami

```csharp
public class OrderMicroservice : BackgroundService
{
    private readonly KeycloakRabbitMQService _rabbitService;
    private readonly ILogger<OrderMicroservice> _logger;

    public OrderMicroservice(
        KeycloakRabbitMQService rabbitService,
        ILogger<OrderMicroservice> logger)
    {
        _rabbitService = rabbitService;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Skonfiguruj topologiê RabbitMQ
        await SetupTopologyAsync();

        // Uruchom konsumentów dla ró¿nych kolejek
        var tasks = new[]
        {
            ConsumeOrdersAsync(stoppingToken),
            ConsumePaymentsAsync(stoppingToken),
            ConsumeInventoryAsync(stoppingToken)
        };

        await Task.WhenAll(tasks);
    }

    private async Task SetupTopologyAsync()
    {
        // Exchange dla zamówieñ
        await _rabbitService.DeclareExchangeAsync("orders", "topic", durable: true);
        
        // Kolejki
        await _rabbitService.DeclareQueueAsync("order.created", durable: true);
        await _rabbitService.DeclareQueueAsync("order.paid", durable: true);
        await _rabbitService.DeclareQueueAsync("order.shipped", durable: true);
        
        // Bindings
        await _rabbitService.BindQueueAsync("order.created", "orders", "order.created");
        await _rabbitService.BindQueueAsync("order.paid", "orders", "order.paid");
        await _rabbitService.BindQueueAsync("order.shipped", "orders", "order.shipped");
    }

    private async Task ConsumeOrdersAsync(CancellationToken cancellationToken)
    {
        await _rabbitService.ConsumeAsync<OrderCreatedEvent>(
            "order.created",
            async order => {
                _logger.LogInformation("Nowe zamówienie: {OrderId}", order.Id);
                await ValidateOrder(order);
                return true;
            },
            cancellationToken: cancellationToken);
    }

    private async Task ConsumePaymentsAsync(CancellationToken cancellationToken)
    {
        await _rabbitService.ConsumeAsync<PaymentProcessedEvent>(
            "order.paid",
            async payment => {
                _logger.LogInformation("P³atnoœæ przetworzona: {OrderId}", payment.OrderId);
                await ProcessPayment(payment);
                return true;
            },
            cancellationToken: cancellationToken);
    }

    private async Task ConsumeInventoryAsync(CancellationToken cancellationToken)
    {
        await _rabbitService.ConsumeAsync<OrderShippedEvent>(
            "order.shipped",
            async shipment => {
                _logger.LogInformation("Zamówienie wys³ane: {OrderId}", shipment.OrderId);
                await UpdateInventory(shipment);
                return true;
            },
            cancellationToken: cancellationToken);
    }
}
```

### Event-driven komunikacja miêdzy serwisami

```csharp
public class EventPublisher
{
    private readonly KeycloakRabbitMQService _rabbitService;

    public EventPublisher(KeycloakRabbitMQService rabbitService)
    {
        _rabbitService = rabbitService;
    }

    public async Task PublishDomainEventAsync<T>(T domainEvent, string eventType)
        where T : class
    {
        var exchange = "domain.events";
        var routingKey = $"event.{eventType}";

        await _rabbitService.DeclareExchangeAsync(exchange, "topic");
        
        await _rabbitService.PublishAsync(
            exchange: exchange,
            routingKey: routingKey,
            message: domainEvent);
    }
}

// U¿ycie w biznes logice
public class OrderService
{
    private readonly EventPublisher _eventPublisher;

    public async Task CreateOrderAsync(CreateOrderCommand command)
    {
        var order = new Order(command);
        await SaveOrderAsync(order);

        // Publikuj event
        await _eventPublisher.PublishDomainEventAsync(
            new OrderCreatedEvent(order.Id, order.CustomerId, order.Amount),
            "order.created");
    }
}
```

### Resilient consumer z retry logic

```csharp
public class ResilientOrderProcessor
{
    private readonly KeycloakRabbitMQService _rabbitService;
    private readonly ILogger<ResilientOrderProcessor> _logger;

    public async Task StartProcessingAsync(CancellationToken cancellationToken)
    {
        // Kolejka g³ówna
        await _rabbitService.DeclareQueueAsync("orders");
        
        // Kolejka dla retry
        await _rabbitService.DeclareQueueAsync("orders.retry", arguments: new Dictionary<string, object>
        {
            ["x-message-ttl"] = 60000, // 1 minuta TTL
            ["x-dead-letter-exchange"] = "orders.dlx",
            ["x-dead-letter-routing-key"] = "orders"
        });
        
        // Dead letter exchange i kolejka
        await _rabbitService.DeclareExchangeAsync("orders.dlx");
        await _rabbitService.DeclareQueueAsync("orders.dead");
        await _rabbitService.BindQueueAsync("orders.dead", "orders.dlx", "orders.failed");

        await _rabbitService.ConsumeAsync<Order>(
            "orders",
            ProcessWithRetryAsync,
            autoAck: false,
            cancellationToken: cancellationToken);
    }

    private async Task<bool> ProcessWithRetryAsync(Order order)
    {
        try
        {
            await ProcessOrder(order);
            return true;
        }
        catch (TransientException ex)
        {
            _logger.LogWarning(ex, "Przejœciowy b³¹d dla zamówienia {OrderId}, wysy³am do retry", order.Id);
            
            // Wyœlij do kolejki retry
            await _rabbitService.PublishAsync("", "orders.retry", order);
            return true; // ACK original message
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Krytyczny b³¹d dla zamówienia {OrderId}, wysy³am do DLQ", order.Id);
            
            // Wyœlij do dead letter queue
            await _rabbitService.PublishAsync("orders.dlx", "orders.failed", order);
            return true; // ACK original message
        }
    }
}
```

## Bezpieczeñstwo

### Minimalne uprawnienia w Keycloak

```json
{
  "roles": [
    "rabbitmq.read:queue/orders.*",
    "rabbitmq.write:exchange/orders",
    "rabbitmq.configure:queue/orders.*"
  ]
}
```

### Konfiguracja SSL dla produkcji

```csharp
services.AddKeycloakRabbitMQ(
    keycloak => {
        keycloak.ServerUrl = "https://keycloak.production.com";
        keycloak.ClientSecret = Environment.GetEnvironmentVariable("KEYCLOAK_SECRET");
        // ...
    },
    rabbitmq => {
        rabbitmq.HostName = "rabbitmq.production.com";
        rabbitmq.Port = 5671; // SSL port
        rabbitmq.UseSsl = true;
        rabbitmq.SslServerName = "rabbitmq.production.com";
        // ...
    });
```

## Testowanie

### Unit tests z mock

```csharp
[Test]
public async Task PublishOrder_ShouldCallRabbitMQService()
{
    // Arrange
    var mockRabbitService = new Mock<KeycloakRabbitMQService>();
    var publisher = new OrderPublisher(mockRabbitService.Object);
    var order = new Order { Id = 123 };

    // Act
    await publisher.PublishOrderAsync(order);

    // Assert
    mockRabbitService.Verify(x => x.PublishAsync(
        "orders", 
        "order.created", 
        order, 
        null, 
        default), Times.Once);
}
```

### Integration tests z TestContainers

```csharp
[Test]
public async Task IntegrationTest_WithRealRabbitMQ()
{
    // Arrange - uruchom RabbitMQ w kontenerze
    using var container = new RabbitMqBuilder()
        .WithPortBinding(5672, true)
        .WithEnvironment("RABBITMQ_DEFAULT_USER", "guest")
        .WithEnvironment("RABBITMQ_DEFAULT_PASS", "guest")
        .Build();
    
    await container.StartAsync();

    var config = new RabbitMQConfig
    {
        HostName = container.Hostname,
        Port = container.GetMappedPublicPort(5672),
        UseKeycloakAuthentication = false,
        Username = "guest",
        Password = "guest"
    };

    // Test logic...
}
```

## Monitoring i diagnostyka

### Metryki z Prometheus

```csharp
public class MetricsCollector
{
    private readonly Counter _messagesPublished = Metrics
        .CreateCounter("rabbitmq_messages_published_total", "Total published messages");
    
    private readonly Counter _messagesConsumed = Metrics
        .CreateCounter("rabbitmq_messages_consumed_total", "Total consumed messages");

    public async Task PublishWithMetricsAsync<T>(
        KeycloakRabbitMQService service,
        string exchange,
        string routingKey,
        T message)
    {
        try
        {
            await service.PublishAsync(exchange, routingKey, message);
            _messagesPublished.Inc();
        }
        catch
        {
            _messagesPublished.WithLabels("failed").Inc();
            throw;
        }
    }
}
```

### Health checks

```csharp
public class RabbitMQHealthCheck : IHealthCheck
{
    private readonly KeycloakRabbitMQConnectionFactory _connectionFactory;

    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        try
        {
            using var connection = await _connectionFactory.CreateConnectionAsync(cancellationToken);
            return connection.IsOpen 
                ? HealthCheckResult.Healthy("RabbitMQ connection is healthy")
                : HealthCheckResult.Unhealthy("RabbitMQ connection is closed");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy("RabbitMQ connection failed", ex);
        }
    }
}

// Program.cs
builder.Services.AddHealthChecks()
    .AddCheck<RabbitMQHealthCheck>("rabbitmq");
```

## Troubleshooting

### Czêste problemy

**1. "JWT authentication failed"**
```bash
# SprawdŸ konfiguracjê Keycloak
# Upewnij siê, ¿e JWKS URL jest dostêpny
curl https://your-keycloak-server.com/realms/your-realm/protocol/openid-connect/certs
```

**2. "Connection refused"**
```bash
# SprawdŸ status RabbitMQ
sudo systemctl status rabbitmq-server
sudo rabbitmq-diagnostics status
```

**3. "Token expired during operation"**
```csharp
// KeycloakService automatycznie odœwie¿a tokeny
// SprawdŸ logi pod k¹tem b³êdów odœwie¿ania
tokenManager.TokenRefreshed += (sender, token) => 
    logger.LogInformation("Token odœwie¿ony: {ExpiresIn}s", token.ExpiresIn);
```

## Dodatkowe zasoby

- [RabbitMQ OAuth2 Plugin Documentation](https://github.com/rabbitmq/rabbitmq-oauth2-tutorial)
- [Keycloak Token Exchange](https://www.keycloak.org/docs/latest/server_admin/#_token-exchange)
- [RabbitMQ.Client .NET Documentation](https://www.rabbitmq.com/dotnet-api-guide.html)

---

Z t¹ integracj¹ masz pe³n¹ kontrolê nad autoryzacj¹ RabbitMQ wykorzystuj¹c tokeny Keycloak, co zapewnia scentralizowane zarz¹dzanie to¿samoœci¹ i uprawnieniami w architekturze mikrous³ug.