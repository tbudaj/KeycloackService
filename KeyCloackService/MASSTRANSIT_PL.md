# KeycloakService - Integracja z MassTransit

Przewodnik po integracji KeycloakService z MassTransit dla autoryzacji RabbitMQ za pomoc� token�w JWT.

## ?? Instalacja

```bash
dotnet add package KeycloakService
dotnet add package MassTransit.RabbitMQ
```

## ?? Konfiguracja

### 1. Konfiguracja appsettings.json

```json
{
  "Keycloak": {
    "ServerUrl": "https://your-keycloak-server.com",
    "Realm": "your-realm",
    "ClientId": "your-client-id",
    "ClientSecret": "your-client-secret",
    "Flow": "ClientCredentials"
  },
  "RabbitMQ": {
    "HostName": "localhost",
    "Port": 5672,
    "VirtualHost": "/"
  }
}
```

### 2. Rejestracja w Program.cs

```csharp
using KeyCloackService.Extensions;
using KeyCloackService.MassTransit;

var builder = WebApplication.CreateBuilder(args);

// Dodaj KeycloakService z obs�ug� MassTransit
builder.Services.AddKeycloakMassTransit();

// Lub z custom konfiguracj�
builder.Services.AddKeycloakMassTransit(keycloak => {
    keycloak.ServerUrl = "https://keycloak.example.com";
    keycloak.Realm = "production";
    keycloak.ClientId = "masstransit-service";
    keycloak.ClientSecret = Environment.GetEnvironmentVariable("KEYCLOAK_SECRET");
    keycloak.Flow = AuthenticationFlow.ClientCredentials;
});

var app = builder.Build();
```

## ?? U�ycie z MassTransit

### Metoda 1: U�ywaj�c Extension Methods (Zalecana)

```csharp
builder.Services.AddMassTransit<ISavingsAccountBus>(cfg =>
{
    cfg.SetEndpointNameFormatter(new KebabCaseEndpointNameFormatter(true));

    cfg.UsingRabbitMq((busContext, rabbitCfg) =>
    {
        // Konfiguruj topologi�
        rabbitCfg.ConfigureScbPublishTopologyFor<Contract.SavingsAccount.Tool.Ping>();
        rabbitCfg.ConfigureScbPublishTopologyFor<Contract.SavingsAccount.Client.StartedLogging>();

        // U�yj Keycloak authentication zamiast UserPasswordProvider
        var keycloakConfig = busContext.UseKeycloakAuthentication(
            builder.Configuration.GetSection("RabbitMQ")["HostName"]!, 
            builder.Configuration.GetValue<int>("RabbitMQ:Port")
        );
        
        rabbitCfg.Host(keycloakConfig);

        rabbitCfg.UseEntityFrameworkCoreAuditStore<AuditDbContext>(
            builder.Configuration.GetConnectionString(Constant.MESSAGE_BROKER_DATABASE_CONNECTION_STRING_KEY), 
            Component.Base.SavingsAccount.EntityFrameworkCoreIntegration.Constant.AuditTable);
    });
});
```

### Metoda 2: Manualna konfiguracja

```csharp
builder.Services.AddMassTransit<ISavingsAccountBus>(cfg =>
{
    cfg.SetEndpointNameFormatter(new KebabCaseEndpointNameFormatter(true));

    cfg.UsingRabbitMq((busContext, rabbitCfg) =>
    {
        rabbitCfg.ConfigureScbPublishTopologyFor<Contract.SavingsAccount.Tool.Ping>();
        rabbitCfg.ConfigureScbPublishTopologyFor<Contract.SavingsAccount.Client.StartedLogging>();

        // Pobierz credentials z Keycloak
        var (username, password) = busContext.GetKeycloakCredentials();
        
        rabbitCfg.Host(builder.Configuration.GetSection("RabbitMQ")["HostName"]!, h =>
        {
            h.Username(username);
            h.Password(password); // JWT token
        });

        rabbitCfg.UseEntityFrameworkCoreAuditStore<AuditDbContext>(
            builder.Configuration.GetConnectionString(Constant.MESSAGE_BROKER_DATABASE_CONNECTION_STRING_KEY), 
            Component.Base.SavingsAccount.EntityFrameworkCoreIntegration.Constant.AuditTable);
    });
});
```

### Metoda 3: U�ywaj�c KeycloakCredentialsProvider bezpo�rednio

```csharp
builder.Services.AddMassTransit<ISavingsAccountBus>(cfg =>
{
    cfg.SetEndpointNameFormatter(new KebabCaseEndpointNameFormatter(true));

    cfg.UsingRabbitMq((busContext, rabbitCfg) =>
    {
        rabbitCfg.ConfigureScbPublishTopologyFor<Contract.SavingsAccount.Tool.Ping>();
        rabbitCfg.ConfigureScbPublishTopologyFor<Contract.SavingsAccount.Client.StartedLogging>();

        // U�yj KeycloakCredentialsProvider
        var credentialsProvider = busContext.GetRequiredService<KeycloakCredentialsProvider>();
        var credentials = credentialsProvider.GetCredentials();
        
        rabbitCfg.Host(builder.Configuration.GetSection("RabbitMQ")["HostName"]!, h =>
        {
            h.Username(credentials.UserName);
            h.Password(credentials.Password); // JWT token
        });

        rabbitCfg.UseEntityFrameworkCoreAuditStore<AuditDbContext>(
            builder.Configuration.GetConnectionString(Constant.MESSAGE_BROKER_DATABASE_CONNECTION_STRING_KEY), 
            Component.Base.SavingsAccount.EntityFrameworkCoreIntegration.Constant.AuditTable);
    });
});
```

## ?? Wymagania RabbitMQ

### W��czenie JWT Authentication Plugin

```bash
rabbitmq-plugins enable rabbitmq_auth_backend_oauth2
```

### Konfiguracja rabbitmq.conf

```ini
# OAuth2/JWT Configuration
auth_backends.1 = oauth2
auth_oauth2.resource_server_id = rabbitmq
auth_oauth2.jwks_url = https://your-keycloak-server.com/realms/your-realm/protocol/openid-connect/certs
auth_oauth2.issuer = https://your-keycloak-server.com/realms/your-realm
auth_oauth2.verify_aud = false
auth_oauth2.scope_prefix = rabbitmq.
```

## ?? Testowanie

### Unit Test z Mock

```csharp
[Test]
public async Task ConfigureBus_ShouldUseKeycloakAuthentication()
{
    // Arrange
    var services = new ServiceCollection();
    var mockTokenManager = new Mock<KeycloakTokenManager>();
    mockTokenManager
        .Setup(x => x.GetAccessTokenAsync(It.IsAny<CancellationToken>()))
        .ReturnsAsync("mock-jwt-token");

    services.AddSingleton(mockTokenManager.Object);
    services.AddKeycloakMassTransit();

    var serviceProvider = services.BuildServiceProvider();

    // Act
    var credentialsProvider = serviceProvider.GetRequiredService<KeycloakCredentialsProvider>();
    var credentials = await credentialsProvider.GetCredentialsAsync();

    // Assert
    Assert.That(credentials.Password, Is.EqualTo("mock-jwt-token"));
}
```

### Integration Test

```csharp
[Test]
public async Task MassTransit_ShouldConnectWithKeycloakAuth()
{
    // Arrange
    var services = new ServiceCollection();
    services.AddKeycloakMassTransit(keycloak =>
    {
        keycloak.ServerUrl = "https://test-keycloak.com";
        keycloak.Realm = "test";
        keycloak.ClientId = "test-client";
        keycloak.ClientSecret = "test-secret";
        keycloak.Flow = AuthenticationFlow.ClientCredentials;
    });

    services.AddMassTransit(cfg =>
    {
        cfg.UsingRabbitMq((context, rabbitCfg) =>
        {
            var keycloakConfig = context.UseKeycloakAuthentication("localhost");
            rabbitCfg.Host(keycloakConfig);
        });
    });

    var serviceProvider = services.BuildServiceProvider();

    // Act & Assert
    var busControl = serviceProvider.GetRequiredService<IBusControl>();
    await busControl.StartAsync(TimeSpan.FromSeconds(30));
    
    Assert.That(busControl.Address, Is.Not.Null);
    
    await busControl.StopAsync();
}
```

## ?? Troubleshooting

### Problem: "KeycloakCredentialsProvider not registered"

**Rozwi�zanie:** Upewnij si�, �e wywo�ujesz `AddKeycloakMassTransit()` przed konfiguracj� MassTransit:

```csharp
// ? B��dna kolejno��
builder.Services.AddMassTransit(/* ... */);
builder.Services.AddKeycloakMassTransit(); // Za p�no!

// ? Poprawna kolejno��  
builder.Services.AddKeycloakMassTransit();
builder.Services.AddMassTransit(/* ... */);
```

### Problem: "JWT authentication failed"

**Rozwi�zanie:** Sprawd� konfiguracj� RabbitMQ OAuth2 plugin:

```bash
# Sprawd� czy plugin jest w��czony
rabbitmq-plugins list | grep oauth2

# Sprawd� JWKS endpoint
curl https://your-keycloak-server.com/realms/your-realm/protocol/openid-connect/certs
```

### Problem: "Token expired during bus startup"

**Rozwi�zanie:** KeycloakService automatycznie od�wie�a tokeny, ale mo�esz skonfigurowa� buffer:

```csharp
services.AddKeycloakMassTransit(keycloak =>
{
    // ...
    keycloak.TokenRefreshBuffer = TimeSpan.FromMinutes(10); // Od�wie� 10 min przed wyga�ni�ciem
});
```

## ?? Monitoring

### Logowanie zdarze� Keycloak

```csharp
var tokenManager = serviceProvider.GetRequiredService<KeycloakTokenManager>();

tokenManager.TokenRefreshed += (sender, token) =>
{
    logger.LogInformation("RabbitMQ JWT token refreshed, expires in {ExpiresIn}s", token.ExpiresIn);
};

tokenManager.AuthenticationFailed += (sender, ex) =>
{
    logger.LogError(ex, "RabbitMQ JWT authentication failed");
};
```

### Health Checks

```csharp
public class RabbitMQKeycloakHealthCheck : IHealthCheck
{
    private readonly KeycloakCredentialsProvider _credentialsProvider;
    private readonly IBusControl _busControl;

    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context, 
        CancellationToken cancellationToken = default)
    {
        try
        {
            // Sprawd� czy mo�na pobra� credentials
            var credentials = await _credentialsProvider.GetCredentialsAsync(cancellationToken);
            
            // Sprawd� czy MassTransit bus jest uruchomiony
            var isHealthy = _busControl.Address != null;
            
            return isHealthy 
                ? HealthCheckResult.Healthy("RabbitMQ with Keycloak JWT is healthy")
                : HealthCheckResult.Unhealthy("RabbitMQ bus is not started");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy("Keycloak authentication failed", ex);
        }
    }
}

// Program.cs
builder.Services.AddHealthChecks()
    .AddCheck<RabbitMQKeycloakHealthCheck>("rabbitmq-keycloak");
```

## ?? Najlepsze praktyki

1. **U�ywaj Client Credentials flow** dla service-to-service communication
2. **Konfiguruj odpowiednie role** w Keycloak dla RabbitMQ
3. **Monitoruj od�wie�anie token�w** przez logi/metryki
4. **Testuj konfiguracj�** na environment testowy przed produkcj�
5. **U�ywaj Health Checks** do monitorowania stanu

## ?? Kompletny przyk�ad

```csharp
using KeyCloackService.Extensions;
using KeyCloackService.MassTransit;
using MassTransit;

var builder = WebApplication.CreateBuilder(args);

// Konfiguracja Keycloak z MassTransit
builder.Services.AddKeycloakMassTransit();

// Konfiguracja MassTransit
builder.Services.AddMassTransit<ISavingsAccountBus>(cfg =>
{
    cfg.SetEndpointNameFormatter(new KebabCaseEndpointNameFormatter(true));

    cfg.UsingRabbitMq((busContext, rabbitCfg) =>
    {
        // Topologia
        rabbitCfg.ConfigureScbPublishTopologyFor<Contract.SavingsAccount.Tool.Ping>();
        rabbitCfg.ConfigureScbPublishTopologyFor<Contract.SavingsAccount.Client.StartedLogging>();

        // Keycloak Authentication - zast�puje UserPasswordProvider
        var keycloakAuth = busContext.UseKeycloakAuthentication(
            builder.Configuration["RabbitMQ:HostName"]!
        );
        rabbitCfg.Host(keycloakAuth);

        // Audit store
        rabbitCfg.UseEntityFrameworkCoreAuditStore<AuditDbContext>(
            builder.Configuration.GetConnectionString("MessageBrokerDb")!, 
            "AuditTable");
    });
});

// Health checks
builder.Services.AddHealthChecks()
    .AddCheck<RabbitMQKeycloakHealthCheck>("rabbitmq-keycloak");

var app = builder.Build();

app.UseHealthChecks("/health");
app.Run();
```

---

Z t� integracj� masz pe�n� kontrol� nad autoryzacj� MassTransit wykorzystuj�c tokeny Keycloak, co zapewnia scentralizowane zarz�dzanie to�samo�ci� i uprawnieniami w architekturze mikrous�ug.