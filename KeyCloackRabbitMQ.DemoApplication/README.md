# KeyCloakRabbitMQ Demo Application

Aplikacja demonstracyjna pokazuj�ca mo�liwo�ci biblioteki KeyCloakService z integracj� RabbitMQ.

## ?? Funkcjonalno�ci

- ? **Autoryzacja RabbitMQ przez Keycloak** - pe�na integracja JWT
- ? **Producer i Consumer** - wysy�anie i odbieranie wiadomo�ci
- ? **API endpoints** - RESTful API do testowania
- ? **Health checks** - sprawdzanie statusu Keycloak i RabbitMQ
- ? **Logowanie na konsoli** - szczeg�owe logi otrzymanych wiadomo�ci
- ? **Swagger UI** - interaktywna dokumentacja API
- ? **R�ne typy wiadomo�ci** - JSON i string messages

## ??? Wymagania

- **.NET 8** lub nowszy
- **Keycloak** dost�pny pod adresem `http://localhost:8080`
- **RabbitMQ** dost�pny pod adresem `localhost:5672`

## ?? Konfiguracja

### Keycloak
1. Uruchom Keycloak na `http://localhost:8080`
2. Utw�rz realm `demo-realm`
3. Utw�rz klienta `rabbitmq-demo-client`
4. Skonfiguruj Client Credentials flow

### RabbitMQ
1. Uruchom RabbitMQ na `localhost:5672`
2. Dla developmentu u�ywany jest basic auth (guest/guest)
3. Dla produkcji skonfiguruj JWT plugin

## ?? Uruchomienie

```bash
cd KeyCloackRabbitMQ.DemoApplication
dotnet restore
dotnet run
```

Aplikacja b�dzie dost�pna pod adresem `https://localhost:5001` (lub `http://localhost:5000`)

## ?? API Endpoints

### Wiadomo�ci
- `POST /api/messages/test` - Wy�lij wiadomo�� testow�
- `POST /api/messages/order` - Wy�lij zam�wienie
- `POST /api/messages/notification` - Wy�lij powiadomienie
- `POST /api/messages/test/bulk` - Wy�lij wiele wiadomo�ci

### Health Checks
- `GET /api/health` - Status wszystkich serwis�w
- `GET /api/health/keycloak` - Status Keycloak
- `GET /api/health/rabbitmq` - Status RabbitMQ

## ?? Przyk�ady u�ycia

### Wys�anie wiadomo�ci testowej
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

### Wys�anie zam�wienia
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

Consumer loguje otrzymane wiadomo�ci na konsoli w j�zyku polskim:

```
?? OTRZYMANO WIADOMO�� TESTOW�:
   ID: 12345678-1234-1234-1234-123456789abc
   Tre��: Hello RabbitMQ!
   Od: DemoApplication
   Timestamp: 2024-01-15 10:30:00
? Wiadomo�� testowa 12345678-1234-1234-1234-123456789abc przetworzona pomy�lnie

?? OTRZYMANO ZAM�WIENIE:
   ID: 1
   Klient: Jan Kowalski
   Produkt: Laptop Dell
   Kwota: 2 500,00 z�
   Data: 2024-01-15 10:30:00
   Status: Created
?? Zam�wienie 1 przesz�o do statusu: Processing
?? Zam�wienie 1 zosta�o wys�ane
? Zam�wienie 1 przetworzone pomy�lnie
```

## ??? Architektura

### Topologia RabbitMQ
- **Exchange**: `demo.events` (topic)
- **Queues**: 
  - `demo.messages` (routing: `message.*`)
  - `demo.orders` (routing: `order.*`)
  - `demo.notifications` (routing: `notification.*`)

### Serwisy
- **MessageProducerService** - wysy�anie wiadomo�ci
- **MessageConsumerService** - odbieranie i przetwarzanie wiadomo�ci (BackgroundService)
- **KeycloakHealthCheck** - sprawdzanie statusu Keycloak
- **RabbitMQHealthCheck** - sprawdzanie statusu RabbitMQ

## ?? Troubleshooting

### Problem z po��czeniem do Keycloak
```
? Failed to initialize RabbitMQ topology
```
- Sprawd� czy Keycloak jest uruchomiony na `http://localhost:8080`
- Zweryfikuj konfiguracj� realm i klienta

### Problem z RabbitMQ
```
? RabbitMQ connection failed
```
- Sprawd� czy RabbitMQ jest uruchomiony na `localhost:5672`
- W trybie development ustaw `UseKeycloakAuthentication: false`

### Brak wiadomo�ci w konsoli
- Sprawd� czy MessageConsumerService zosta� uruchomiony
- Zweryfikuj topologi� RabbitMQ w Management UI

## ?? Dodatkowe informacje

- Swagger UI dost�pne na g��wnej stronie aplikacji
- Health checks dost�pne pod `/api/health`
- Wszystkie operacje s� asynchroniczne
- Graceful shutdown obs�uguje anulowanie consumer�w