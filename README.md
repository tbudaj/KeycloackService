# KeycloakService - .NET Keycloak Token Manager

Complete .NET library for managing Keycloak tokens with automatic refresh and support for all major OAuth2/OpenID Connect flows.

## 🚀 Features

- ✅ **5 main OAuth2/OIDC authorization flows**
- 🔄 **Automatic token refresh**
- 🔐 **Thread-safe operations**
- ⚡ **Asynchronous API**
- 🛡️ **PKCE Support** for enhanced security
- 📱 **Device Flow** for IoT/CLI devices
- 🔍 **Token validation & introspection**
- 📊 **Event-driven architecture**
- 🧩 **HttpClient extensions**

## 📋 Supported Authorization Flows

| Flow                          | Use case            | Security       | Refresh Token |
|-------------------------------|---------------------|----------------|---------------|
| **Password Credentials**      | Desktop/Mobile apps | Średnie        | ✅            |
| **Client Credentials**        | Service-to-Service  | Wysokie        | ❌            |
| **Authorization Code**        | Web aplikacje       | Najwyższe      | ✅            |
| **Authorization Code + PKCE** | Mobile/SPA          | Najwyższe      | ✅            |
| **Device Flow**               | IoT/CLI/Smart TV    | Wysokie        | ✅            |

### PackageReference
```xml
<PackageReference Include="KeycloakService" Version="1.0.0" />
```

## 📚 Quick Start

### 1. Basic Configuration

```csharp
using KeyCloackService;

// Password Flow (for desktop/mobile applications)
var config = new KeycloakConfig
{
    ServerUrl = "https://your-keycloak-server.com",
    Realm = "your-realm",
    ClientId = "your-client-id",
    Username = "user@example.com",
    Password = "password123",
    Flow = AuthenticationFlow.Password
};

using var tokenManager = new KeycloakTokenManager(config);
```

### 2. Getting Tokens

```csharp
// Automatic token management - background refresh
var accessToken = await tokenManager.GetAccessTokenAsync();

// Using with HttpClient
var httpClient = new HttpClient();
await httpClient.SetBearerTokenAsync(tokenManager);

var response = await httpClient.GetAsync("https://your-api.com/protected-endpoint");
```

## 🔐 Authorization Flows Guide

### Password Flow (Resource Owner Password Credentials)
**Ideal for:** Desktop apps, mobile apps with direct access to user credentials

```csharp
var config = new KeycloakConfig
{
    ServerUrl = "https://keycloak.example.com",
    Realm = "my-realm",
    ClientId = "desktop-app",
    Username = "user@company.com",
    Password = "userpassword",
    ClientSecret = "optional-for-confidential-clients",
    Flow = AuthenticationFlow.Password
};

using var tokenManager = new KeycloakTokenManager(config);
var token = await tokenManager.GetAccessTokenAsync();
```

### Client Credentials Flow
**Ideal for:** Service-to-service communication, backend APIs

```csharp
var config = new KeycloakConfig
{
    ServerUrl = "https://keycloak.example.com",
    Realm = "my-realm",
    ClientId = "backend-service",
    ClientSecret = "service-secret-123",
    Flow = AuthenticationFlow.ClientCredentials
};

using var tokenManager = new KeycloakTokenManager(config);
var token = await tokenManager.GetAccessTokenAsync();
```

### Authorization Code Flow
**Ideal for:** Web applications with backend

```csharp
var config = new KeycloakConfig
{
    ServerUrl = "https://keycloak.example.com",
    Realm = "my-realm",
    ClientId = "web-app",
    ClientSecret = "web-app-secret",
    RedirectUri = "https://myapp.com/callback",
    Flow = AuthenticationFlow.AuthorizationCode
};

using var tokenManager = new KeycloakTokenManager(config);

// 1. Redirect user to Keycloak
var authUrl = tokenManager.GetAuthorizationUrl();
Response.Redirect(authUrl);

// 2. In callback endpoint
var token = await tokenManager.ExchangeCodeForTokenAsync(authorizationCode, state);
```

### Authorization Code + PKCE Flow
**Ideal for:** Mobile apps, Single Page Applications (SPA)

```csharp
var codeVerifier = PKCEHelper.GenerateCodeVerifier();
var config = new KeycloakConfig
{
    ServerUrl = "https://keycloak.example.com",
    Realm = "my-realm",
    ClientId = "mobile-app",
    RedirectUri = "com.yourapp://callback",
    CodeVerifier = codeVerifier,
    Flow = AuthenticationFlow.AuthorizationCodePKCE
};

using var tokenManager = new KeycloakTokenManager(config);

// Use in-app browser for authorization
var authUrl = tokenManager.GetAuthorizationUrl();
// After receiving authorization code
var token = await tokenManager.ExchangeCodeForTokenAsync(code);
```

### Device Flow
**Ideal for:** IoT devices, CLI tools, Smart TV

```csharp
var config = new KeycloakConfig
{
    ServerUrl = "https://keycloak.example.com",
    Realm = "my-realm",
    ClientId = "iot-device",
    Flow = AuthenticationFlow.DeviceFlow,
    DeviceFlowTimeout = TimeSpan.FromMinutes(15)
};

using var tokenManager = new KeycloakTokenManager(config);

// Event handling
tokenManager.DeviceAuthorizationStarted += (sender, deviceAuth) =>
{
    Console.WriteLine($"Visit: {deviceAuth.VerificationUri}");
    Console.WriteLine($"Enter code: {deviceAuth.UserCode}");
    DisplayQRCode(deviceAuth.VerificationUriComplete);
};

// Automatic polling and authentication
var token = await tokenManager.AuthenticateAsync();
```

## 🔄 Advanced Usage

### Event Handling

```csharp
tokenManager.TokenRefreshed += (sender, tokenResponse) =>
{
    Console.WriteLine($"Token refreshed! Expires in: {tokenResponse.ExpiresIn}s");
    // You can save token to cache, database, etc.
    await SaveTokenToCache(tokenResponse.AccessToken);
};

tokenManager.AuthenticationFailed += (sender, exception) =>
{
    logger.LogError(exception, "Keycloak authentication failed");
    // Implement retry logic, fallback, etc.
};

tokenManager.DeviceAuthorizationStarted += (sender, deviceAuth) =>
{
    // Display instructions for user in Device Flow
    ShowUserInstructions(deviceAuth.VerificationUri, deviceAuth.UserCode);
};
```

### Token Validation

```csharp
// Simple validation
bool isValid = await tokenManager.ValidateTokenAsync(userToken);

// Detailed introspection
var introspection = await tokenManager.IntrospectTokenAsync(userToken);
Console.WriteLine($"Token active: {introspection.Active}");
Console.WriteLine($"Username: {introspection.Username}");
Console.WriteLine($"Expires at: {DateTimeOffset.FromUnixTimeSeconds(introspection.Exp ?? 0)}");
```

### Token Monitoring

```csharp
// Check if token expired
if (tokenManager.IsTokenExpired())
{
    Console.WriteLine("Token expired, will refresh on next request");
}

// Time until expiration
var timeLeft = tokenManager.GetTimeUntilExpiry();
if (timeLeft.HasValue)
{
    Console.WriteLine($"Token expires in: {timeLeft.Value}");
}

// Current token (without triggering refresh)
var currentToken = tokenManager.GetCurrentToken();
```

### HttpClient Integration

```csharp
var httpClient = new HttpClient();

// Automatic Bearer token setup
await httpClient.SetBearerTokenAsync(tokenManager);

// Manual setup
var token = await tokenManager.GetAccessTokenAsync();
httpClient.SetBearerToken(token);

// Clear Bearer token
httpClient.ClearBearerToken();
```

## 🏭 Dependency Injection (ASP.NET Core)

### Configuration in Program.cs

```csharp
// Program.cs
services.AddSingleton<KeycloakConfig>(serviceProvider => 
{
    var configuration = serviceProvider.GetRequiredService<IConfiguration>();
    return new KeycloakConfig
    {
        ServerUrl = configuration["Keycloak:ServerUrl"]!,
        Realm = configuration["Keycloak:Realm"]!,
        ClientId = configuration["Keycloak:ClientId"]!,
        ClientSecret = configuration["Keycloak:ClientSecret"],
        Flow = Enum.Parse<AuthenticationFlow>(configuration["Keycloak:Flow"]!)
    };
});

services.AddScoped<KeycloakTokenManager>();
services.AddHttpClient();
```

### appsettings.json

```json
{
  "Keycloak": {
    "ServerUrl": "https://your-keycloak-server.com",
    "Realm": "your-realm",
    "ClientId": "your-client-id",
    "ClientSecret": "your-client-secret",
    "Flow": "ClientCredentials"
  }
}
```

### Usage in Service

```csharp
public class ApiService
{
    private readonly KeycloakTokenManager _tokenManager;
    private readonly HttpClient _httpClient;

    public ApiService(KeycloakTokenManager tokenManager, HttpClient httpClient)
    {
        _tokenManager = tokenManager;
        _httpClient = httpClient;
    }

    public async Task<string> GetProtectedDataAsync()
    {
        await _httpClient.SetBearerTokenAsync(_tokenManager);
        var response = await _httpClient.GetAsync("https://api.example.com/protected");
        return await response.Content.ReadAsStringAsync();
    }
}
```

## ⚙️ Configuration

### KeycloakConfig Properties

| Property            | Type               | Description                                         |
|---------------------|--------------------|-----------------------------------------------------|
| `ServerUrl`         | string             | Keycloak server URL                                 |
| `Realm`             | string             | Keycloak realm name                                 |
| `ClientId`          | string             | Client ID                                           |
| `ClientSecret`      | string?            | Client secret (required for confidential clients)   |
| `Username`          | string?            | Username (for Password flow)                        |
| `Password`          | string?            | Password (for Password flow)                        |
| `Flow`              | AuthenticationFlow | Authentication flow (default: Password)             |
| `RedirectUri`       | string?            | Redirect URI (for Authorization Code flows)         |
| `Scopes`            | string?            | OAuth scopes (default: "openid profile email")      |
| `TokenRefreshBuffer`| TimeSpan?          | Refresh buffer time (default: 5 minutes)            |
| `CodeVerifier`      | string?            | PKCE code verifier (auto-generated if not provided) |
| `DeviceFlowTimeout` | TimeSpan           | Device flow timeout (default: 10 minutes)           |

## 🚪 Logout and Cleanup

```csharp
// Logout from Keycloak (invalidates refresh token)
await tokenManager.LogoutAsync();

// Local token cleanup
tokenManager.ClearTokens();

// Proper disposal
tokenManager.Dispose();
```

## 🛡️ Security

### Best Practices

1. **Store secrets securely**
```csharp
ClientSecret = Environment.GetEnvironmentVariable("KEYCLOAK_SECRET")
```

2. **Always use HTTPS**
```csharp
ServerUrl = "https://keycloak.yourdomain.com" // ✅
ServerUrl = "http://keycloak.yourdomain.com"  // ❌
```

3. **Use appropriate flow for your application**
   - Web apps → Authorization Code
   - Mobile/SPA → Authorization Code + PKCE
   - Service-to-Service → Client Credentials
   - IoT/CLI → Device Flow

4. **Handle errors gracefully**
```csharp
try
{
    var token = await tokenManager.GetAccessTokenAsync();
}
catch (KeycloakAuthenticationException ex)
{
    logger.LogError(ex, "Authentication failed");
    // Implement retry logic or fallback
}
```

## 🔧 Integration Examples

### Web API Controller

```csharp
[ApiController]
[Route("api/[controller]")]
public class SecureController : ControllerBase
{
    private readonly KeycloakTokenManager _tokenManager;
    private readonly HttpClient _httpClient;

    public SecureController(KeycloakTokenManager tokenManager, HttpClient httpClient)
    {
        _tokenManager = tokenManager;
        _httpClient = httpClient;
    }

    [HttpGet("protected-data")]
    public async Task<IActionResult> GetProtectedData()
    {
        try
        {
            await _httpClient.SetBearerTokenAsync(_tokenManager);
            var response = await _httpClient.GetAsync("https://external-api.com/data");
            
            if (response.IsSuccessStatusCode)
            {
                var data = await response.Content.ReadAsStringAsync();
                return Ok(data);
            }
            
            return StatusCode((int)response.StatusCode);
        }
        catch (KeycloakAuthenticationException ex)
        {
            return Unauthorized(ex.Message);
        }
    }
}
```

### Background Service

```csharp
public class DataSyncService : BackgroundService
{
    private readonly KeycloakTokenManager _tokenManager;
    private readonly ILogger<DataSyncService> _logger;

    public DataSyncService(KeycloakTokenManager tokenManager, ILogger<DataSyncService> logger)
    {
        _tokenManager = tokenManager;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await SyncData(stoppingToken);
                await Task.Delay(TimeSpan.FromMinutes(15), stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during data sync");
            }
        }
    }

    private async Task SyncData(CancellationToken cancellationToken)
    {
        var httpClient = new HttpClient();
        await httpClient.SetBearerTokenAsync(_tokenManager, cancellationToken);
        
        // Perform API calls...
    }
}
```

## 📊 Monitoring and Diagnostics

### Logging

```csharp
// Configure events with ILogger
tokenManager.TokenRefreshed += (sender, token) =>
{
    logger.LogInformation("Token refreshed successfully. Expires in {ExpiresIn}s", token.ExpiresIn);
};

tokenManager.AuthenticationFailed += (sender, ex) =>
{
    logger.LogWarning(ex, "Authentication failed: {Message}", ex.Message);
};
```

### Metrics

```csharp
// Example with custom metrics
tokenManager.TokenRefreshed += (sender, token) =>
{
    metrics.Counter("keycloak_token_refreshes_total").Increment();
    metrics.Histogram("keycloak_token_lifetime_seconds").Observe(token.ExpiresIn);
};

tokenManager.AuthenticationFailed += (sender, ex) =>
{
    metrics.Counter("keycloak_auth_failures_total").Increment();
};
```

## 🧪 Testing

### Unit Tests

```csharp
[Test]
public async Task GetAccessToken_ShouldReturnValidToken()
{
    // Arrange
    var config = new KeycloakConfig
    {
        ServerUrl = "https://test-keycloak.com",
        Realm = "test-realm",
        ClientId = "test-client",
        ClientSecret = "test-secret",
        Flow = AuthenticationFlow.ClientCredentials
    };

    var httpClient = new HttpClient(mockHandler);
    using var tokenManager = new KeycloakTokenManager(config, httpClient);

    // Act
    var token = await tokenManager.GetAccessTokenAsync();

    // Assert
    Assert.That(token, Is.Not.Null.And.Not.Empty);
}
```

### Integration Tests

```csharp
[Test]
public async Task AuthenticateAsync_WithValidCredentials_ShouldSucceed()
{
    // Arrange
    var config = TestConfiguration.GetValidConfig();
    using var tokenManager = new KeycloakTokenManager(config);

    // Act & Assert
    Assert.DoesNotThrowAsync(async () =>
    {
        var response = await tokenManager.AuthenticateAsync();
        Assert.That(response.AccessToken, Is.Not.Null.And.Not.Empty);
    });
}
```

## 🐛 Troubleshooting

### Common Issues

**1. "ClientSecret is required for ClientCredentials flow"**
```csharp
// Solution: Add ClientSecret for Client Credentials flow
var config = new KeycloakConfig
{
    // ...
    ClientSecret = "your-client-secret", // ✅ Required
    Flow = AuthenticationFlow.ClientCredentials
};
```

**2. "RedirectUri is required for Authorization Code flows"**
```csharp
// Solution: Add RedirectUri for Authorization Code flows
var config = new KeycloakConfig
{
    // ...
    RedirectUri = "https://yourapp.com/callback", // ✅ Required
    Flow = AuthenticationFlow.AuthorizationCode
};
```

**3. "Device flow authentication timed out"**
```csharp
// Solution: Increase timeout for Device Flow
var config = new KeycloakConfig
{
    // ...
    DeviceFlowTimeout = TimeSpan.FromMinutes(20), // ✅ Longer timeout
    Flow = AuthenticationFlow.DeviceFlow
};
```

# KeycloakService - RabbitMQ Integration

Complete guide for integrating KeycloakService with RabbitMQ for message queue authorization.

## RabbitMQ Features

- **JWT Authorization** - uses Keycloak tokens for RabbitMQ authentication
- **Automatic connection refresh** - during token renewal
- **Thread-safe operations** - safe multi-threaded operations
- **Asynchronous API** - all operations use async/await
- **Publish and consume** - complete messaging API
- **Topology management** - queues, exchanges, bindings
- **Dependency Injection** - full integration with ASP.NET Core

## Requirements

- **RabbitMQ Server** with JWT Authentication plugin enabled
- **Keycloak Server** with properly configured client
- **.NET 8** or newer

## RabbitMQ Configuration

### Enable JWT Authentication in RabbitMQ

1. **Enable JWT plugin**:
```bash
rabbitmq-plugins enable rabbitmq_auth_backend_oauth2
```

2. **Configure RabbitMQ** (`rabbitmq.conf`):
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

### Keycloak Configuration

1. **Create RabbitMQ client** in Keycloak Admin Console
2. **Configure permissions** (scopes/roles) for RabbitMQ queues
3. **Add mappers** to tokens (e.g., audience mapper)

## Basic Usage

### 1. appsettings.json Configuration

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

### 2. Program.cs Configuration

```csharp
using KeyCloackService.Extensions;

var builder = WebApplication.CreateBuilder(args);

// Add KeycloakService with RabbitMQ support
builder.Services.AddKeycloakRabbitMQ();

// Or with custom configuration
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

### 3. Publishing Messages

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
        // Declare exchange and queue
        await _rabbitService.DeclareExchangeAsync("orders", "topic");
        await _rabbitService.DeclareQueueAsync("order.created");
        await _rabbitService.BindQueueAsync("order.created", "orders", "order.created");

        // Publish message
        await _rabbitService.PublishAsync(
            exchange: "orders",
            routingKey: "order.created", 
            message: order);
    }
}
```

### 4. Consuming Messages

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
        // Declare infrastructure
        await _rabbitService.DeclareQueueAsync("order.created");

        // Start consuming
        await _rabbitService.ConsumeAsync<Order>(
            queueName: "order.created",
            onMessage: ProcessOrderAsync,
            autoAck: false,
            cancellationToken: stoppingToken);

        // Keep service running
        await Task.Delay(Timeout.Infinite, stoppingToken);
    }

    private async Task<bool> ProcessOrderAsync(Order order)
    {
        try
        {
            _logger.LogInformation("Processing order {OrderId}", order.Id);
            
            // Process order
            await ProcessBusinessLogic(order);
            
            _logger.LogInformation("Order {OrderId} processed successfully", order.Id);
            return true; // ACK
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing order {OrderId}", order.Id);
            return false; // NACK - message will be reprocessed
        }
    }
}
```

## Advanced Scenarios

### Microservice with Multiple Queues

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
        // Setup RabbitMQ topology
        await SetupTopologyAsync();

        // Start consumers for different queues
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
        // Exchange for orders
        await _rabbitService.DeclareExchangeAsync("orders", "topic", durable: true);
        
        // Queues
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
                _logger.LogInformation("New order: {OrderId}", order.Id);
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
                _logger.LogInformation("Payment processed: {OrderId}", payment.OrderId);
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
                _logger.LogInformation("Order shipped: {OrderId}", shipment.OrderId);
                await UpdateInventory(shipment);
                return true;
            },
            cancellationToken: cancellationToken);
    }
}
```

### Event-driven Communication Between Services

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

// Usage in business logic
public class OrderService
{
    private readonly EventPublisher _eventPublisher;

    public async Task CreateOrderAsync(CreateOrderCommand command)
    {
        var order = new Order(command);
        await SaveOrderAsync(order);

        // Publish event
        await _eventPublisher.PublishDomainEventAsync(
            new OrderCreatedEvent(order.Id, order.CustomerId, order.Amount),
            "order.created");
    }
}
```

### Resilient Consumer with Retry Logic

```csharp
public class ResilientOrderProcessor
{
    private readonly KeycloakRabbitMQService _rabbitService;
    private readonly ILogger<ResilientOrderProcessor> _logger;

    public async Task StartProcessingAsync(CancellationToken cancellationToken)
    {
        // Main queue
        await _rabbitService.DeclareQueueAsync("orders");
        
        // Retry queue
        await _rabbitService.DeclareQueueAsync("orders.retry", arguments: new Dictionary<string, object>
        {
            ["x-message-ttl"] = 60000, // 1 minute TTL
            ["x-dead-letter-exchange"] = "orders.dlx",
            ["x-dead-letter-routing-key"] = "orders"
        });
        
        // Dead letter exchange and queue
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
            _logger.LogWarning(ex, "Transient error for order {OrderId}, sending to retry", order.Id);
            
            // Send to retry queue
            await _rabbitService.PublishAsync("", "orders.retry", order);
            return true; // ACK original message
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Critical error for order {OrderId}, sending to DLQ", order.Id);
            
            // Send to dead letter queue
            await _rabbitService.PublishAsync("orders.dlx", "orders.failed", order);
            return true; // ACK original message
        }
    }
}
```

## Security

### Minimal Permissions in Keycloak

```json
{
  "roles": [
    "rabbitmq.read:queue/orders.*",
    "rabbitmq.write:exchange/orders",
    "rabbitmq.configure:queue/orders.*"
  ]
}
```

### SSL Configuration for Production

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

## Testing

### Unit Tests with Mocks

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

### Integration Tests with TestContainers

```csharp
[Test]
public async Task IntegrationTest_WithRealRabbitMQ()
{
    // Arrange - run RabbitMQ in container
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

## Monitoring and Diagnostics

### Metrics with Prometheus

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

### Health Checks

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

### Common Issues

**1. "JWT authentication failed"**
```bash
# Check Keycloak configuration
# Ensure JWKS URL is accessible
curl https://your-keycloak-server.com/realms/your-realm/protocol/openid-connect/certs
```

**2. "Connection refused"**
```bash
# Check RabbitMQ status
sudo systemctl status rabbitmq-server
sudo rabbitmq-diagnostics status
```

**3. "Token expired during operation"**
```csharp
// KeycloakService automatically refreshes tokens
// Check logs for refresh errors
tokenManager.TokenRefreshed += (sender, token) => 
    logger.LogInformation("Token refreshed: {ExpiresIn}s", token.ExpiresIn);
```

## Additional Resources

- [RabbitMQ OAuth2 Plugin Documentation](https://github.com/rabbitmq/rabbitmq-oauth2-tutorial)
- [Keycloak Token Exchange](https://www.keycloak.org/docs/latest/server_admin/#_token-exchange)
- [RabbitMQ.Client .NET Documentation](https://www.rabbitmq.com/dotnet-api-guide.html)

---

With this integration, you have full control over RabbitMQ authorization using Keycloak tokens, providing centralized identity and permission management in microservice architectures.
