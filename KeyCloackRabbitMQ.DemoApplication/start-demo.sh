#!/bin/bash

echo "?? Uruchamianie KeyCloak RabbitMQ Demo Environment..."

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "? Docker is not running. Please start Docker first."
    exit 1
fi

echo "?? Starting Keycloak and RabbitMQ services..."
docker-compose up -d

echo "? Waiting for services to start..."
sleep 30

echo "?? Checking service status..."

# Check Keycloak
echo "Checking Keycloak..."
if curl -f http://localhost:8080/health > /dev/null 2>&1; then
    echo "? Keycloak is running at http://localhost:8080"
else
    echo "? Keycloak is still starting..."
fi

# Check RabbitMQ
echo "Checking RabbitMQ..."
if curl -f http://localhost:15672 > /dev/null 2>&1; then
    echo "? RabbitMQ Management UI is running at http://localhost:15672"
else
    echo "? RabbitMQ is still starting..."
fi

echo ""
echo "?? Next steps:"
echo "1. Configure Keycloak realm and client (see KEYCLOAK_RABBITMQ_SETUP.md)"
echo "2. Run the demo application: dotnet run"
echo ""
echo "?? Useful URLs:"
echo "   Keycloak Admin: http://localhost:8080/admin (admin/admin)"
echo "   RabbitMQ Management: http://localhost:15672 (admin/admin)"
echo "   Demo App: http://localhost:5156"