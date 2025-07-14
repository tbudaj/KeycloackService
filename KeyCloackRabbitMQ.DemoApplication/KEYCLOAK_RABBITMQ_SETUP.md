# Konfiguracja Keycloak dla RabbitMQ JWT Authentication

## ?? Szybkie uruchomienie œrodowiska

### 1. Uruchomienie stacku
```bash
cd KeyCloakRabbitMQ.DemoApplication
docker-compose up -d
```

### 2. Dostêp do serwisów
- **Keycloak Admin Console**: http://localhost:8080/admin
  - Username: `admin`
  - Password: `admin`
- **RabbitMQ Management**: http://localhost:15672
  - Username: `admin`
  - Password: `admin`

## ?? Konfiguracja Keycloak

### 1. Stwórz Realm (jeœli nie istnieje)
1. PrzejdŸ do Keycloak Admin Console
2. Kliknij dropdown w lewym górnym rogu (tam gdzie "master")
3. Kliknij "Create realm"
4. Wpisz: `WebAppMetrics`
5. Kliknij "Create"

### 2. Stwórz Client dla RabbitMQ
1. W realm `WebAppMetrics` przejdŸ do **Clients**
2. Kliknij **Create client**
3. Wype³nij:
   - **Client type**: `OpenID Connect`
   - **Client ID**: `WebAppMetrics` (jak w appsettings.json)
   - **Name**: `RabbitMQ Demo Client`
4. Kliknij **Next**
5. W³¹cz:
   - ? **Client authentication**
   - ? **Service accounts roles**
   - ? **Standard flow** (wy³¹cz)
   - ? **Direct access grants** (wy³¹cz)
6. Kliknij **Save**

### 3. Skonfiguruj Client Settings
1. W zak³adce **Settings**:
   - **Access Type**: `confidential`
   - **Service Accounts Enabled**: `ON`
   - **Authorization Enabled**: `ON`

2. W zak³adce **Credentials**:
   - Skopiuj **Secret** i wstaw do `appsettings.json` jako `ClientSecret`

### 4. Dodaj Role dla RabbitMQ
1. PrzejdŸ do **Realm roles**
2. Kliknij **Create role**
3. Dodaj role:
   - `rabbitmq.read:queue/*`
   - `rabbitmq.write:exchange/*` 
   - `rabbitmq.configure:queue/*`
   - `rabbitmq.tag:administrator`

### 5. Przypisz Role do Service Account
1. W **Clients** ? `WebAppMetrics` ? **Service accounts roles**
2. Kliknij **Assign role**
3. Wybierz wszystkie utworzone role RabbitMQ
4. Kliknij **Assign**

### 6. Skonfiguruj Token Mappers
1. W **Clients** ? `WebAppMetrics` ? **Client scopes**
2. Kliknij na scope z sufiksem `-dedicated`
3. Kliknij **Add mapper** ? **By configuration**
4. Wybierz **User Realm Role**
5. Wype³nij:
   - **Name**: `rabbitmq-roles`
   - **Token Claim Name**: `permissions`
   - **Claim JSON Type**: `String`
   - **Add to ID token**: `ON`
   - **Add to access token**: `ON`

## ?? Testowanie konfiguracji

### Test tokenu Keycloak
```bash
curl -X POST \
  http://localhost:8080/realms/WebAppMetrics/protocol/openid-connect/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials&client_id=WebAppMetrics&client_secret=YOUR_CLIENT_SECRET'
```

### SprawdŸ JWKS endpoint
```bash
curl http://localhost:8080/realms/WebAppMetrics/protocol/openid-connect/certs
```

## ?? W³¹czenie JWT w aplikacji

Po skonfigurowaniu Keycloak i RabbitMQ, zmieñ w `appsettings.json`:

```json
{
  "RabbitMQ": {
    "UseKeycloakAuthentication": true,
    "HostName": "localhost",
    "Port": 5672
  }
}
```

I usuñ `Username`/`Password` z konfiguracji RabbitMQ.

## ?? Troubleshooting

### Problem: "JWT authentication failed"
1. SprawdŸ czy RabbitMQ ma w³¹czony plugin OAuth2
2. Zweryfikuj JWKS URL w konfiguracji RabbitMQ
3. SprawdŸ czy token ma odpowiednie role/permissions

### Problem: "Connection refused"
1. SprawdŸ czy RabbitMQ jest uruchomiony z poprawn¹ konfiguracj¹
2. SprawdŸ logi RabbitMQ: `docker logs rabbitmq-demo`

### Sprawdzenie tokenów
U¿yj https://jwt.io do dekodowania tokenów i sprawdzenia claims.