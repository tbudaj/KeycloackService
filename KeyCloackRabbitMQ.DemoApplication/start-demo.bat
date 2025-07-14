@echo off
echo ?? Uruchamianie KeyCloak RabbitMQ Demo Environment...

REM Check if Docker is running
docker info >nul 2>&1
if errorlevel 1 (
    echo ? Docker is not running. Please start Docker first.
    exit /b 1
)

echo ?? Starting Keycloak and RabbitMQ services...
docker-compose up -d

echo ? Waiting for services to start...
timeout /t 30 /nobreak >nul

echo ?? Checking service status...

REM Check Keycloak
echo Checking Keycloak...
curl -f http://localhost:8080/health >nul 2>&1
if errorlevel 1 (
    echo ? Keycloak is still starting...
) else (
    echo ? Keycloak is running at http://localhost:8080
)

REM Check RabbitMQ
echo Checking RabbitMQ...
curl -f http://localhost:15672 >nul 2>&1
if errorlevel 1 (
    echo ? RabbitMQ is still starting...
) else (
    echo ? RabbitMQ Management UI is running at http://localhost:15672
)

echo.
echo ?? Next steps:
echo 1. Configure Keycloak realm and client (see KEYCLOAK_RABBITMQ_SETUP.md)
echo 2. Run the demo application: dotnet run
echo.
echo ?? Useful URLs:
echo    Keycloak Admin: http://localhost:8080/admin (admin/admin)
echo    RabbitMQ Management: http://localhost:15672 (admin/admin)
echo    Demo App: http://localhost:5156

pause