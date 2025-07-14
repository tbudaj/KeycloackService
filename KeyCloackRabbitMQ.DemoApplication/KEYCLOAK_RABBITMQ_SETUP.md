# Konfiguracja Keycloak dla RabbitMQ JWT Authentication

## ?? Szybkie uruchomienie �rodowiska

### 1. Uruchomienie stacku
```bash
cd KeyCloakRabbitMQ.DemoApplication
docker-compose up -d
```

### 2. Dost�p do serwis�w
- **Keycloak Admin Console**: http://localhost:8080/admin
  - Username: `admin`
  - Password: `admin`
- **RabbitMQ Management**: http://localhost:15672
  - Username: `admin`
  - Password: `admin`

## ?? Konfiguracja Keycloak

### 1. Stw�rz Realm (je�li nie istnieje)
1. Przejd� do Keycloak Admin Console
2. Kliknij dropdown w lewym g�rnym rogu (tam gdzie "master")
3. Kliknij "Create realm"
4. Wpisz: `WebAppMetrics`
5. Kliknij "Create"

### 2. Stw�rz Client dla RabbitMQ
1. W realm `WebAppMetrics` przejd� do **Clients**
2. Kliknij **Create client**
3. Wype�nij:
   - **Client type**: `OpenID Connect`
   - **Client ID**: `WebAppMetrics` (jak w appsettings.json)
   - **Name**: `RabbitMQ Demo Client`
4. Kliknij **Next**
5. W��cz:
   - ? **Client authentication**
   - ? **Service accounts roles**
   - ? **Standard flow** (wy��cz)
   - ? **Direct access grants** (wy��cz)
6. Kliknij **Save**

### 3. Skonfiguruj Client Settings
1. W zak�adce **Settings**:
   - **Access Type**: `confidential`
   - **Service Accounts Enabled**: `ON`
   - **Authorization Enabled**: `ON`

2. W zak�adce **Credentials**:
   - Skopiuj **Secret** i wstaw do `appsettings.json` jako `ClientSecret`

### 4. Dodaj Role dla RabbitMQ
1. Przejd� do **Realm roles**
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
5. Wype�nij:
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

### Sprawd� JWKS endpoint
```bash
curl http://localhost:8080/realms/WebAppMetrics/protocol/openid-connect/certs
```

## ?? W��czenie JWT w aplikacji

Po skonfigurowaniu Keycloak i RabbitMQ, zmie� w `appsettings.json`:

```json
{
  "RabbitMQ": {
    "UseKeycloakAuthentication": true,
    "HostName": "localhost",
    "Port": 5672
  }
}
```

I usu� `Username`/`Password` z konfiguracji RabbitMQ.

## ?? Troubleshooting

### Problem: "JWT authentication failed"
1. Sprawd� czy RabbitMQ ma w��czony plugin OAuth2
2. Zweryfikuj JWKS URL w konfiguracji RabbitMQ
3. Sprawd� czy token ma odpowiednie role/permissions

### Problem: "Connection refused"
1. Sprawd� czy RabbitMQ jest uruchomiony z poprawn� konfiguracj�
2. Sprawd� logi RabbitMQ: `docker logs rabbitmq-demo`

### Sprawdzenie token�w
U�yj https://jwt.io do dekodowania token�w i sprawdzenia claims.