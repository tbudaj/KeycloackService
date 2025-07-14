# KeyCloakRabbitMQ Demo Application

Aplikacja demonstracyjna pokazuj¹ca mo¿liwoœci biblioteki KeyCloakService z integracj¹ RabbitMQ.

## ?? Funkcjonalnoœci

- ? **Autoryzacja RabbitMQ przez Keycloak** - pe³na integracja JWT
- ? **Producer i Consumer** - wysy³anie i odbieranie wiadomoœci
- ? **API endpoints** - RESTful API do testowania
- ? **Health checks** - sprawdzanie statusu Keycloak i RabbitMQ
- ? **Logowanie na konsoli** - szczegó³owe logi otrzymanych wiadomoœci
- ? **Swagger UI** - interaktywna dokumentacja API
- ? **Ró¿ne typy wiadomoœci** - JSON i string messages

## ??? Wymagania

- **.NET 8** lub nowszy
- **Keycloak** dostêpny pod adresem `http://localhost:8080`
- **RabbitMQ** dostêpny pod adresem `localhost:5672`

## ?? Konfiguracja

### Keycloak
1. Uruchom Keycloak na `http://localhost:8080`
2. Utwórz realm `demo-realm`
3. Utwórz klienta `rabbitmq-demo-client`
4. Skonfiguruj Client Credentials flow

### RabbitMQ
1. Uruchom RabbitMQ na `localhost:5672`
2. Dla developmentu u¿ywany jest basic auth (guest/guest)
3. Dla produkcji skonfiguruj JWT plugin

## ?? Uruchomienie

```bash
cd KeyCloackRabbitMQ.DemoApplication
dotnet restore
dotnet run
```

Aplikacja bêdzie dostêpna pod adresem `https://localhost:5001` (lub `http://localhost:5000`)

## ?? API Endpoints

### Wiadomoœci
- `POST /api/messages/test` - Wyœlij wiadomoœæ testow¹
- `POST /api/messages/order` - Wyœlij zamówienie
- `POST /api/messages/notification` - Wyœlij powiadomienie
- `POST /api/messages/test/bulk` - Wyœlij wiele wiadomoœci

### Health Checks
- `GET /api/health` - Status wszystkich serwisów
- `GET /api/health/keycloak` - Status Keycloak
- `GET /api/health/rabbitmq` - Status RabbitMQ

## ?? Przyk³ady u¿ycia

### Wys³anie wiadomoœci testowej
```json
POST /api/messages/test
{
  "content": "Hello RabbitMQ!",
  "metadata": {
    "priority": "high",
    "source": "demo"
  }
}
```

### Wys³anie zamówienia
```json
POST /api/messages/order
{
  "id": 1,
  "customerName": "Jan Kowalski",
  "productName": "Laptop Dell",
  "amount": 2500.00
}
```

## ?? Logowanie

Consumer loguje otrzymane wiadomoœci na konsoli w jêzyku polskim:

```
?? OTRZYMANO WIADOMOŒÆ TESTOW¥:
   ID: 12345678-1234-1234-1234-123456789abc
   Treœæ: Hello RabbitMQ!
   Od: DemoApplication
   Timestamp: 2024-01-15 10:30:00
? Wiadomoœæ testowa 12345678-1234-1234-1234-123456789abc przetworzona pomyœlnie

?? OTRZYMANO ZAMÓWIENIE:
   ID: 1
   Klient: Jan Kowalski
   Produkt: Laptop Dell
   Kwota: 2 500,00 z³
   Data: 2024-01-15 10:30:00
   Status: Created
?? Zamówienie 1 przesz³o do statusu: Processing
?? Zamówienie 1 zosta³o wys³ane
? Zamówienie 1 przetworzone pomyœlnie
```

## ??? Architektura

### Topologia RabbitMQ
- **Exchange**: `demo.events` (topic)
- **Queues**: 
  - `demo.messages` (routing: `message.*`)
  - `demo.orders` (routing: `order.*`)
  - `demo.notifications` (routing: `notification.*`)

### Serwisy
- **MessageProducerService** - wysy³anie wiadomoœci
- **MessageConsumerService** - odbieranie i przetwarzanie wiadomoœci (BackgroundService)
- **KeycloakHealthCheck** - sprawdzanie statusu Keycloak
- **RabbitMQHealthCheck** - sprawdzanie statusu RabbitMQ

## ?? Troubleshooting

### Problem z po³¹czeniem do Keycloak
```
? Failed to initialize RabbitMQ topology
```
- SprawdŸ czy Keycloak jest uruchomiony na `http://localhost:8080`
- Zweryfikuj konfiguracjê realm i klienta

### Problem z RabbitMQ
```
? RabbitMQ connection failed
```
- SprawdŸ czy RabbitMQ jest uruchomiony na `localhost:5672`
- W trybie development ustaw `UseKeycloakAuthentication: false`

### Brak wiadomoœci w konsoli
- SprawdŸ czy MessageConsumerService zosta³ uruchomiony
- Zweryfikuj topologiê RabbitMQ w Management UI

## ?? Dodatkowe informacje

- Swagger UI dostêpne na g³ównej stronie aplikacji
- Health checks dostêpne pod `/api/health`
- Wszystkie operacje s¹ asynchroniczne
- Graceful shutdown obs³uguje anulowanie consumerów