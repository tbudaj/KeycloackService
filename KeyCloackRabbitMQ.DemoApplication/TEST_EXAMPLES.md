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
### Wys³anie wielu wiadomoœci testowych
curl -X POST "http://localhost:5156/api/messages/test/bulk" \
     -H "accept: application/json" \
     -H "Content-Type: application/json" \
     -d '[
       {
         "content": "Pierwsza wiadomoœæ",
         "metadata": { "batch": "1" }
       },
       {
         "content": "Druga wiadomoœæ", 
         "metadata": { "batch": "1" }
       },
       {
         "content": "Trzecia wiadomoœæ",
         "metadata": { "batch": "1" }
       }
     ]'
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
## ?? Oczekiwane logi w konsoli

Po uruchomieniu aplikacji:
? Services registered successfully
?? Application built successfully
?? KeyCloak RabbitMQ Demo Application is starting...
?? Swagger UI available at: http://localhost:5156
?? Test endpoint available at: http://localhost:5156/test
?? Health checks available at: http://localhost:5156/api/health
?? Messages API available at: http://localhost:5156/api/messages
Po wys³aniu wiadomoœci testowej powinieneœ zobaczyæ w konsoli:
info: KeyCloackRabbitMQ.DemoApplication.Services.MessageProducerService[0]
      Test message sent: 12345678-1234-1234-1234-123456789abc - Hello from demo application!

info: KeyCloackRabbitMQ.DemoApplication.Services.MessageConsumerService[0]
      ?? OTRZYMANO WIADOMOŒÆ TESTOW¥:
info: KeyCloackRabbitMQ.DemoApplication.Services.MessageConsumerService[0]
         ID: 12345678-1234-1234-1234-123456789abc
info: KeyCloackRabbitMQ.DemoApplication.Services.MessageConsumerService[0]
         Treœæ: Hello from demo application!
info: KeyCloackRabbitMQ.DemoApplication.Services.MessageConsumerService[0]
         Od: DemoApplication
info: KeyCloackRabbitMQ.DemoApplication.Services.MessageConsumerService[0]
         Timestamp: 15.01.2024 10:30:00
info: KeyCloackRabbitMQ.DemoApplication.Services.MessageConsumerService[0]
         Metadata:
info: KeyCloackRabbitMQ.DemoApplication.Services.MessageConsumerService[0]
           priority: high
info: KeyCloackRabbitMQ.DemoApplication.Services.MessageConsumerService[0]
           source: test-script
info: KeyCloackRabbitMQ.DemoApplication.Services.MessageConsumerService[0]
      ? Wiadomoœæ testowa 12345678-1234-1234-1234-123456789abc przetworzona pomyœlnie
## ?? PowerShell Examples (Windows)
# Basic test
Invoke-RestMethod -Uri "http://localhost:5156/test" -Method GET

# Health check
Invoke-RestMethod -Uri "http://localhost:5156/api/health" -Method GET

# Send test message
$body = @{
    content = "Hello from PowerShell!"
    metadata = @{
        source = "powershell"
        priority = "medium"
    }
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:5156/api/messages/test" -Method POST -Body $body -ContentType "application/json"

# Send order
$order = @{
    id = 99999
    customerName = "Anna Nowak"
    productName = "MacBook Pro"
    amount = 8999.99
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:5156/api/messages/order" -Method POST -Body $order -ContentType "application/json"
## ?? Krok po kroku testowania

1. **Podstawowy test**: `http://localhost:5156/test`
   - Sprawdza czy aplikacja odpowiada

2. **Test kontrolera**: `http://localhost:5156/api/test`
   - Sprawdza czy ASP.NET Core routing dzia³a

3. **Health check**: `http://localhost:5156/api/health`
   - Sprawdza status Keycloak i RabbitMQ

4. **Wys³anie wiadomoœci**: `POST http://localhost:5156/api/messages/test`
   - Testuje pe³n¹ funkcjonalnoœæ producer/consumer

5. **Swagger UI**: `http://localhost:5156`
   - Interaktywne testowanie wszystkich endpoint'ów