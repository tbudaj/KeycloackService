# Test Examples for KeyCloakRabbitMQ Demo Application

## ?? Przyk³ady testów API

### Sprawdzenie czy aplikacja dzia³a
curl -X GET "http://localhost:5156/test" -H "accept: application/json"

### Sprawdzenie statusu aplikacji
curl -X GET "http://localhost:5156/api/health" -H "accept: application/json"

### Sprawdzenie statusu Keycloak
curl -X GET "http://localhost:5156/api/health/keycloak" -H "accept: application/json"

### Sprawdzenie statusu RabbitMQ
curl -X GET "http://localhost:5156/api/health/rabbitmq" -H "accept: application/json"

### Test podstawowego kontrolera
curl -X GET "http://localhost:5156/api/test" -H "accept: application/json"

## ?? Publiczne endpoint'y (bez autoryzacji)

### Wys³anie wiadomoœci testowej
curl -X POST "http://localhost:5156/api/messages/test" \
     -H "accept: application/json" \
     -H "Content-Type: application/json" \
     -d '{
       "content": "Hello from demo application!",
       "metadata": {
         "priority": "high",
         "source": "test-script"
       }
     }'

### Wys³anie zamówienia
curl -X POST "http://localhost:5156/api/messages/order" \
     -H "accept: application/json" \
     -H "Content-Type: application/json" \
     -d '{
       "id": 12345,
       "customerName": "Jan Kowalski",
       "productName": "Laptop Dell XPS 13",
       "amount": 4500.00
     }'

### Wys³anie powiadomienia
curl -X POST "http://localhost:5156/api/messages/notification" \
     -H "accept: application/json" \
     -H "Content-Type: application/json" \
     -d '"Testowe powiadomienie z API"'

## ?? JWT Authentication

### Pobranie tokenu JWT (wymagane u¿ytkownik w Keycloak)
curl -X POST "http://localhost:5156/api/auth/token" \
     -H "accept: application/json" \
     -H "Content-Type: application/json" \
     -d '{
       "username": "demo-user",
       "password": "demo-password"
     }'

### Informacje o konfiguracji autoryzacji
curl -X GET "http://localhost:5156/api/auth/info" \
     -H "accept: application/json"

### Odœwie¿enie tokenu JWT
curl -X POST "http://localhost:5156/api/auth/refresh" \
     -H "accept: application/json" \
     -H "Content-Type: application/json" \
     -d '{
       "refreshToken": "YOUR_REFRESH_TOKEN_HERE"
     }'

## ?? Zabezpieczone endpoint'y (wymagaj¹ JWT token)

**Uwaga:** Wszystkie poni¿sze ¿¹dania wymagaj¹ nag³ówka Authorization z JWT tokenem:-H "Authorization: Bearer YOUR_JWT_TOKEN_HERE"
### Test autoryzacji
curl -X GET "http://localhost:5156/api/secure-messages/auth-test" \
     -H "accept: application/json" \
     -H "Authorization: Bearer YOUR_JWT_TOKEN_HERE"

### Profil u¿ytkownika
curl -X GET "http://localhost:5156/api/secure-messages/profile" \
     -H "accept: application/json" \
     -H "Authorization: Bearer YOUR_JWT_TOKEN_HERE"

### Zabezpieczona wiadomoœæ testowa
curl -X POST "http://localhost:5156/api/secure-messages/test" \
     -H "accept: application/json" \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer YOUR_JWT_TOKEN_HERE" \
     -d '{
       "content": "Secured message from authenticated user!",
       "metadata": {
         "priority": "high",
         "source": "secure-api"
       }
     }'

### Zabezpieczone zamówienie
curl -X POST "http://localhost:5156/api/secure-messages/order" \
     -H "accept: application/json" \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer YOUR_JWT_TOKEN_HERE" \
     -d '{
       "id": 99999,
       "customerName": "Anna Secure",
       "productName": "MacBook Pro Secured",
       "amount": 8999.99
     }'

### Zabezpieczone powiadomienie
curl -X POST "http://localhost:5156/api/secure-messages/notification" \
     -H "accept: application/json" \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer YOUR_JWT_TOKEN_HERE" \
     -d '"Secured notification from authenticated user"'

### Zabezpieczone masowe wysy³anie
curl -X POST "http://localhost:5156/api/secure-messages/test/bulk" \
     -H "accept: application/json" \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer YOUR_JWT_TOKEN_HERE" \
     -d '{
       "content": "Pierwsza secured wiadomoœæ",
       "metadata": { "batch": "secure-1" }
     }'

### Bezpoœrednie wys³anie do kolejki (secured)
curl -X POST "http://localhost:5156/api/secure-messages/test/direct" \
     -H "accept: application/json" \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer YOUR_JWT_TOKEN_HERE" \
     -d '{
       "content": "Direct secured message",
       "metadata": {
         "directSend": true,
         "priority": "high"
       }
     }'

## ?? Oczekiwane odpowiedzi

### Podstawowy test aplikacji
{
  "message": "Application is working!",
  "timestamp": "2024-01-15T10:30:00.000Z"
}
### Test kontrolera
{
  "message": "Application is working!",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "environment": "Development",
  "machineName": "YOUR-MACHINE-NAME"
}
### Pomyœlna odpowiedŸ - wiadomoœæ testowa
{
  "success": true,
  "data": {
    "id": "12345678-1234-1234-1234-123456789abc",
    "content": "Hello from demo application!",
    "timestamp": "2024-01-15T10:30:00.000Z",
    "from": "DemoApplication",
    "metadata": {
      "priority": "high",
      "source": "test-script"
    }
  },
  "message": "Test message sent successfully",
  "timestamp": "2024-01-15T10:30:00.000Z"
}
### Pomyœlna odpowiedŸ - health check
{
  "success": true,
  "data": {
    "status": "Healthy",
    "totalDuration": "00:00:00.0123456",
    "checks": [
      {
        "service": "keycloak",
        "isHealthy": true,
        "status": "Healthy",
        "details": "Keycloak is accessible and authentication is working",
        "checkedAt": "2024-01-15T10:30:00.000Z"
      },
      {
        "service": "rabbitmq",
        "isHealthy": true,
        "status": "Healthy", 
        "details": "RabbitMQ connection is healthy",
        "checkedAt": "2024-01-15T10:30:00.000Z"
      }
    ]
  },
  "message": "All services are healthy",
  "timestamp": "2024-01-15T10:30:00.000Z"
}
### Pomyœlne pobranie tokenu JWT
{
  "success": true,
  "data": {
    "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6...",
    "tokenType": "Bearer",
    "expiresIn": 3600,
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6...",
    "scope": "openid profile email",
    "issuedAt": "2024-01-15T10:30:00.000Z",
    "expiresAt": "2024-01-15T11:30:00.000Z"
  },
  "message": "Token retrieved successfully"
}
### Test autoryzacji
{
  "success": true,
  "data": {
    "message": "JWT Authentication successful!",
    "userName": "demo-user",
    "userId": "12345678-1234-1234-1234-123456789abc",
    "timestamp": "2024-01-15T10:30:00.000Z"
  },
  "message": "Authentication test passed"
}
### Profil u¿ytkownika
{
  "success": true,
  "data": {
    "userId": "12345678-1234-1234-1234-123456789abc",
    "userName": "demo-user",
    "email": "demo@example.com",
    "roles": ["user", "demo-role"],
    "claims": [
      {"type": "sub", "value": "12345678-1234-1234-1234-123456789abc"},
      {"type": "preferred_username", "value": "demo-user"}
    ],
    "tokenExpiry": "2024-01-15T11:30:00.000Z",
    "issuer": "http://localhost:8080/realms/WebAppMetrics"
  },
  "message": "User profile retrieved successfully"
}
## ?? PowerShell Examples (Windows)

### Pobranie tokenu$tokenRequest = @{
    username = "demo-user"
    password = "demo-password"
} | ConvertTo-Json

$tokenResponse = Invoke-RestMethod -Uri "http://localhost:5156/api/auth/token" -Method POST -Body $tokenRequest -ContentType "application/json"
$token = $tokenResponse.data.accessToken
### U¿ycie tokenu do zabezpieczonych wywo³añ$headers = @{
    "Authorization" = "Bearer $token"
}

# Test autoryzacji
Invoke-RestMethod -Uri "http://localhost:5156/api/secure-messages/auth-test" -Method GET -Headers $headers

# Wys³anie zabezpieczonej wiadomoœci
$secureMessage = @{
    content = "Hello from PowerShell with JWT!"
    metadata = @{
        source = "powershell-secure"
        priority = "high"
    }
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:5156/api/secure-messages/test" -Method POST -Body $secureMessage -ContentType "application/json" -Headers $headers
## ?? Krok po kroku testowania

### 1. Podstawowe testy (bez autoryzacji)
1. **Podstawowy test**: `http://localhost:5156/test`
2. **Health check**: `http://localhost:5156/api/health`
3. **Publiczna wiadomoœæ**: `POST /api/messages/test`

### 2. Autoryzacja JWT
1. **Informacje o auth**: `GET /api/auth/info`
2. **Pobranie tokenu**: `POST /api/auth/token` (wymagane: username/password)
3. **Test tokenu**: `GET /api/secure-messages/auth-test`

### 3. Zabezpieczone operacje
1. **Profil u¿ytkownika**: `GET /api/secure-messages/profile`
2. **Zabezpieczona wiadomoœæ**: `POST /api/secure-messages/test`
3. **Zabezpieczone zamówienie**: `POST /api/secure-messages/order`

### 4. Swagger UI z autoryzacj¹
1. Otwórz: `http://localhost:5156`
2. Kliknij **Authorize** (ikona k³ódki)
3. Wpisz: `Bearer YOUR_JWT_TOKEN_HERE`
4. Testuj zabezpieczone endpoint'y

## ?? Oczekiwane logi w konsoli

### Po autoryzacji u¿ytkownika:?? JWT token issued successfully for user demo-user
?? JWT Token validated for user: demo-user
### Po wys³aniu zabezpieczonej wiadomoœci:?? Secured test message sent via API by user demo-user (12345678-1234-1234-1234-123456789abc): message-id
?? OTRZYMANO WIADOMOŒÆ TESTOW¥:
   ID: message-id
   Treœæ: Secured message content
   Od: SecureAPI-demo-user
   Metadata:
     authorizedUser: demo-user
     userId: 12345678-1234-1234-1234-123456789abc
     source: SecureAPI
? Wiadomoœæ testowa przetworzona pomyœlnie