# KeycloakService - .NET Keycloak Token Manager

Kompletna biblioteka .NET do zarządzania tokenami Keycloak z automatycznym odświeżaniem i obsługą wszystkich głównych przepływów OAuth2/OpenID Connect.

## ?? Funkcjonalności

- ? **5 głównych przepływów autoryzacji OAuth2/OIDC**
- ?? **Automatyczne odświeżanie tokenów**
- ?? **Thread-safe operations**
- ? **Asynchroniczne API**
- ??? **PKCE Support** dla zwiększonego bezpieczeństwa
- ?? **Device Flow** dla urządzeń IoT/CLI
- ?? **Token validation & introspection**
- ?? **Event-driven architecture**
- ?? **HttpClient extensions**

## ?? Obsługiwane przepływy autoryzacji

| Przepływ                      | Użycie              | Bezpieczeństwo | Refresh Token |
|-------------------------------|---------------------|----------------|---------------|
| **Password Credentials**      | Desktop/Mobile apps | Średnie        | ✅            |
| **Client Credentials**        | Service-to-Service  | Wysokie        | ❌            |
| **Authorization Code**        | Web aplikacje       | Najwyższe      | ✅            |
| **Authorization Code + PKCE** | Mobile/SPA          | Najwyższe      | ✅            |
| **Device Flow**               | IoT/CLI/Smart TV    | Wysokie        | ✅            |

## ??? Instalacja

### Package Manager
```powershell
Install-Package KeycloakService
```

### .NET CLI
```bash
dotnet add package KeycloakService
```

### PackageReference
```xml
<PackageReference Include="KeycloakService" Version="1.0.0" />
```

## ?? Szybki start

### 1. Podstawowa konfiguracja

```csharp
using KeyCloackService;

// Password Flow (dla aplikacji desktop/mobile)
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

### 2. Pobieranie tokenów

```csharp
// Automatyczne zarządzanie tokenami - odświeżanie w tle
var accessToken = await tokenManager.GetAccessTokenAsync();

// Używanie z HttpClient
var httpClient = new HttpClient();
await httpClient.SetBearerTokenAsync(tokenManager);

var response = await httpClient.GetAsync("https://your-api.com/protected-endpoint");
```

## ?? Przewodnik po przepływach autoryzacji

### Password Flow (Resource Owner Password Credentials)
**Ideal dla:** Desktop apps, mobile apps z bezpośrednim dostępem do danych użytkownika

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
**Ideal dla:** Service-to-service communication, backend APIs

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
**Ideal dla:** Web aplikacje z backend

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

// 1. Przekieruj użytkownika do Keycloak
var authUrl = tokenManager.GetAuthorizationUrl();
Response.Redirect(authUrl);

// 2. W callback endpoint
var token = await tokenManager.ExchangeCodeForTokenAsync(authorizationCode, state);
```

### Authorization Code + PKCE Flow
**Ideal dla:** Mobile apps, Single Page Applications (SPA)

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

// Użyj in-app browser dla autoryzacji
var authUrl = tokenManager.GetAuthorizationUrl();
// Po otrzymaniu authorization code
var token = await tokenManager.ExchangeCodeForTokenAsync(code);
```

### Device Flow
**Ideal dla:** IoT devices, CLI tools, Smart TV

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

// Obsługa eventów
tokenManager.DeviceAuthorizationStarted += (sender, deviceAuth) =>
{
    Console.WriteLine($"Visit: {deviceAuth.VerificationUri}");
    Console.WriteLine($"Enter code: {deviceAuth.UserCode}");
    DisplayQRCode(deviceAuth.VerificationUriComplete);
};

// Automatyczne polling i uwierzytelnianie
var token = await tokenManager.AuthenticateAsync();
```

## ?? Zaawansowane użycie

### Event Handling

```csharp
tokenManager.TokenRefreshed += (sender, tokenResponse) =>
{
    Console.WriteLine($"Token refreshed! Expires in: {tokenResponse.ExpiresIn}s");
    // Możesz zapisać token do cache, bazy danych, itp.
    await SaveTokenToCache(tokenResponse.AccessToken);
};

tokenManager.AuthenticationFailed += (sender, exception) =>
{
    logger.LogError(exception, "Keycloak authentication failed");
    // Implementuj retry logic, fallback, itp.
};

tokenManager.DeviceAuthorizationStarted += (sender, deviceAuth) =>
{
    // Wyświetl instrukcje dla użytkownika w Device Flow
    ShowUserInstructions(deviceAuth.VerificationUri, deviceAuth.UserCode);
};
```

### Token Validation

```csharp
// Prosta walidacja
bool isValid = await tokenManager.ValidateTokenAsync(userToken);

// Szczegółowa introspection
var introspection = await tokenManager.IntrospectTokenAsync(userToken);
Console.WriteLine($"Token active: {introspection.Active}");
Console.WriteLine($"Username: {introspection.Username}");
Console.WriteLine($"Expires at: {DateTimeOffset.FromUnixTimeSeconds(introspection.Exp ?? 0)}");
```

### Monitoring tokenu

```csharp
// Sprawdzenie czy token wygasł
if (tokenManager.IsTokenExpired())
{
    Console.WriteLine("Token expired, will refresh on next request");
}

// Czas do wygaśnięcia
var timeLeft = tokenManager.GetTimeUntilExpiry();
if (timeLeft.HasValue)
{
    Console.WriteLine($"Token expires in: {timeLeft.Value}");
}

// Obecny token (bez triggering refresh)
var currentToken = tokenManager.GetCurrentToken();
```

### HttpClient Integration

```csharp
var httpClient = new HttpClient();

// Automatyczne ustawienie Bearer token
await httpClient.SetBearerTokenAsync(tokenManager);

// Manualne ustawienie
var token = await tokenManager.GetAccessTokenAsync();
httpClient.SetBearerToken(token);

// Usunięcie Bearer token
httpClient.ClearBearerToken();
```

## ?? Dependency Injection (ASP.NET Core)

### Konfiguracja w Program.cs

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

### Użycie w serwisie

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

## ?? Konfiguracja

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

## ?? Logout i cleanup

```csharp
// Wylogowanie z Keycloak (invaliduje refresh token)
await tokenManager.LogoutAsync();

// Lokalne czyszczenie tokenów
tokenManager.ClearTokens();

// Proper disposal
tokenManager.Dispose();
```

## ??? Bezpieczeństwo

### Najlepsze praktyki

1. **Przechowuj sekrety bezpiecznie**
```csharp
ClientSecret = Environment.GetEnvironmentVariable("KEYCLOAK_SECRET")
```

2. **Używaj HTTPS zawsze**
```csharp
ServerUrl = "https://keycloak.yourdomain.com" // ?
ServerUrl = "http://keycloak.yourdomain.com"  // ?
```

3. **Używaj odpowiedniego flow dla aplikacji**
   - Web apps ? Authorization Code
   - Mobile/SPA ? Authorization Code + PKCE
   - Service-to-Service ? Client Credentials
   - IoT/CLI ? Device Flow

4. **Obsługuj błędy gracefully**
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

## ?? Przykłady integracji

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

## ?? Monitoring i diagnostyka

### Logowanie

```csharp
// Konfiguracja eventów z ILogger
tokenManager.TokenRefreshed += (sender, token) =>
{
    logger.LogInformation("Token refreshed successfully. Expires in {ExpiresIn}s", token.ExpiresIn);
};

tokenManager.AuthenticationFailed += (sender, ex) =>
{
    logger.LogWarning(ex, "Authentication failed: {Message}", ex.Message);
};
```

### Metryki

```csharp
// Przykład z custom metrics
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

## ?? Testowanie

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

## ?? Troubleshooting

### Częste problemy

**1. "ClientSecret is required for ClientCredentials flow"**
```csharp
// Rozwiązanie: Dodaj ClientSecret dla Client Credentials flow
var config = new KeycloakConfig
{
    // ...
    ClientSecret = "your-client-secret", // ? Wymagane
    Flow = AuthenticationFlow.ClientCredentials
};
```

**2. "RedirectUri is required for Authorization Code flows"**
```csharp
// Rozwiązanie: Dodaj RedirectUri dla Authorization Code flows
var config = new KeycloakConfig
{
    // ...
    RedirectUri = "https://yourapp.com/callback", // ? Wymagane
    Flow = AuthenticationFlow.AuthorizationCode
};
```

**3. "Device flow authentication timed out"**
```csharp
// Rozwiązanie: Zwiększ timeout dla Device Flow
var config = new KeycloakConfig
{
    // ...
    DeviceFlowTimeout = TimeSpan.FromMinutes(20), // ? Dłuższy timeout
    Flow = AuthenticationFlow.DeviceFlow
};
```
