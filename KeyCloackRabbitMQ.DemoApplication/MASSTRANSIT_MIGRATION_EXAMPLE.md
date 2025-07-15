# Przyk�ady u�ycia KeycloakService z MassTransit

## ?? Konfiguracja MassTransit z Keycloak JWT

Poni�ej znajduj� si� przyk�ady jak zast�pi� `UserPasswordProvider` w MassTransit konfiguracj� Keycloak JWT.

### Oryginalny kod (z UserPasswordProvider)

```csharp
builder.Services.AddMassTransit<ISavingsAccountBus>(cfg =>
{
    cfg.SetEndpointNameFormatter(new KebabCaseEndpointNameFormatter(true));

    cfg.UsingRabbitMq((busContext, rabbitCfg) =>
    {
        rabbitCfg.ConfigureScbPublishTopologyFor<Contract.SavingsAccount.Tool.Ping>();
        rabbitCfg.ConfigureScbPublishTopologyFor<Contract.SavingsAccount.Client.StartedLogging>();

        // ? Stara metoda z username/password
        rabbitCfg.ConfigureBus(busContext, massTransitConfiguration[nameof(ISavingsAccountBus)], 
            new UserPasswordProvider(rabbitMqAuthenticationConfiguration));

        rabbitCfg.UseEntityFrameworkCoreAuditStore<AuditDbContext>(
            builder.Configuration.GetConnectionString(Constant.MESSAGE_BROKER_DATABASE_CONNECTION_STRING_KEY), 
            Component.Base.SavingsAccount.EntityFrameworkCoreIntegration.Constant.AuditTable);
    });
});
```

### ? Nowy kod z Keycloak JWT

#### Metoda 1: U�ywaj�c Extension Methods (Zalecana)

```csharp
using KeyCloackService.Extensions;
using KeyCloackService.MassTransit;

// Dodaj Keycloak support dla MassTransit
builder.Services.AddKeycloakMassTransit();

builder.Services.AddMassTransit<ISavingsAccountBus>(cfg =>
{
    cfg.SetEndpointNameFormatter(new KebabCaseEndpointNameFormatter(true));

    cfg.UsingRabbitMq((busContext, rabbitCfg) =>
    {
        rabbitCfg.ConfigureScbPublishTopologyFor<Contract.SavingsAccount.Tool.Ping>();
        rabbitCfg.ConfigureScbPublishTopologyFor<Contract.SavingsAccount.Client.StartedLogging>();

        // ? Nowa metoda z Keycloak JWT - zast�puje UserPasswordProvider
        var (username, password) = busContext.GetKeycloakCredentials();
        
        rabbitCfg.Host(builder.Configuration["RabbitMQ:HostName"]!, h =>
        {
            h.Username(username);        // Username z JWT token (sub claim)
            h.Password(password);        // JWT token jako has�o
        });

        rabbitCfg.UseEntityFrameworkCoreAuditStore<AuditDbContext>(
            builder.Configuration.GetConnectionString(Constant.MESSAGE_BROKER_DATABASE_CONNECTION_STRING_KEY), 
            Component.Base.SavingsAccount.EntityFrameworkCoreIntegration.Constant.AuditTable);
    });
});
```

#### Metoda 2: U�ywaj�c KeycloakCredentialsProvider bezpo�rednio

```csharp
using KeyCloackService.Extensions;
using KeyCloackService.MassTransit;

// Dodaj Keycloak support dla MassTransit
builder.Services.AddKeycloakMassTransit();

builder.Services.AddMassTransit<ISavingsAccountBus>(cfg =>
{
    cfg.SetEndpointNameFormatter(new KebabCaseEndpointNameFormatter(true));

    cfg.UsingRabbitMq((busContext, rabbitCfg) =>
    {
        rabbitCfg.ConfigureScbPublishTopologyFor<Contract.SavingsAccount.Tool.Ping>();
        rabbitCfg.ConfigureScbPublishTopologyFor<Contract.SavingsAccount.Client.StartedLogging>();

        // ? U�yj KeycloakCredentialsProvider zamiast UserPasswordProvider
        var credentialsProvider = busContext.GetRequiredService<KeycloakCredentialsProvider>();
        var credentials = credentialsProvider.GetCredentials();
        
        rabbitCfg.Host(builder.Configuration["RabbitMQ:HostName"]!, h =>
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

#### Metoda 3: Z async credentials (zalecana dla lepszej wydajno�ci)

```csharp
using KeyCloackService.Extensions;
using KeyCloackService.MassTransit;

// Dodaj Keycloak support dla MassTransit
builder.Services.AddKeycloakMassTransit();

builder.Services.AddMassTransit<ISavingsAccountBus>(cfg =>
{
    cfg.SetEndpointNameFormatter(new KebabCaseEndpointNameFormatter(true));

    cfg.UsingRabbitMq(async (busContext, rabbitCfg) =>
    {
        rabbitCfg.ConfigureScbPublishTopologyFor<Contract.SavingsAccount.Tool.Ping>();
        rabbitCfg.ConfigureScbPublishTopologyFor<Contract.SavingsAccount.Client.StartedLogging>();

        // ? Async version dla lepszej wydajno�ci
        var (username, password) = await busContext.GetKeycloakCredentialsAsync();
        
        rabbitCfg.Host(builder.Configuration["RabbitMQ:HostName"]!, h =>
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

## ?? Konfiguracja appsettings.json

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

## ?? G��wne r�nice

| Aspekt | UserPasswordProvider | KeycloakCredentialsProvider |
|--------|---------------------|---------------------------|
| **Autoryzacja** | Username/Password | JWT Token z Keycloak |
| **Bezpiecze�stwo** | Statyczne credentials | Dynamiczne tokeny z auto-refresh |
| **Centralizacja** | Lokalne zarz�dzanie | Scentralizowane w Keycloak |
| **Wyga�ni�cie** | Brak automatycznego odnawiania | Automatyczne odnawianie token�w |
| **Auditowanie** | Ograniczone | Pe�ne logi w Keycloak |

## ?? Wymagania RabbitMQ

Aby u�ywa� JWT token�w, RabbitMQ musi mie� skonfigurowany OAuth2 plugin:

```bash
# W��cz plugin
rabbitmq-plugins enable rabbitmq_auth_backend_oauth2

# Restart RabbitMQ
sudo systemctl restart rabbitmq-server
```

Konfiguracja `rabbitmq.conf`:

```ini
auth_backends.1 = oauth2
auth_oauth2.resource_server_id = rabbitmq
auth_oauth2.jwks_url = https://your-keycloak-server.com/realms/your-realm/protocol/openid-connect/certs
auth_oauth2.issuer = https://your-keycloak-server.com/realms/your-realm
auth_oauth2.verify_aud = false
auth_oauth2.scope_prefix = rabbitmq.
```

## ?? Korzy�ci przej�cia na Keycloak

1. **Scentralizowane zarz�dzanie to�samo�ci�**
2. **Automatyczne odnawianie token�w**
3. **Lepsza kontrola uprawnie�**
4. **Audit trail w Keycloak**
5. **Zgodno�� z standardami OAuth2/OIDC**
6. **Mo�liwo�� integracji z innymi systemami**

## ?? Migration Checklist

- [ ] Skonfiguruj Keycloak realm i klienta
- [ ] W��cz OAuth2 plugin w RabbitMQ
- [ ] Dodaj `AddKeycloakMassTransit()` do DI
- [ ] Zast�p `UserPasswordProvider` z `KeycloakCredentialsProvider`
- [ ] Zaktualizuj `appsettings.json`
- [ ] Przetestuj po��czenie
- [ ] Skonfiguruj monitoring

Ta migracja zapewni znacznie lepsze bezpiecze�stwo i elastyczno�� w zarz�dzaniu autoryzacj� RabbitMQ!