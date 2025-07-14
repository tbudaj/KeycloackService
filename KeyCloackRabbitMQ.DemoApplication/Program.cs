using KeyCloackService.Extensions;
using KeyCloackRabbitMQ.DemoApplication.Services;

var builder = WebApplication.CreateBuilder(args);

Console.WriteLine("?? Building application...");

// Add services to the container
builder.Services.AddControllers();

// Add Swagger/OpenAPI
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new() { 
        Title = "KeyCloak RabbitMQ Demo API", 
        Version = "v1",
        Description = "Demo application showcasing KeyCloak Service with RabbitMQ integration"
    });
});

// Add logging first
builder.Logging.AddConsole();
builder.Logging.SetMinimumLevel(LogLevel.Information);

try
{
    Console.WriteLine("?? Registering KeyCloak and RabbitMQ services...");
    
    // Add KeyCloak and RabbitMQ services with error handling
    builder.Services.AddKeycloakRabbitMQ();
    builder.Services.AddSingleton<MessageProducerService>();
    builder.Services.AddHostedService<MessageConsumerService>();

    // Add health checks
    builder.Services.AddHealthChecks()
        .AddCheck<KeycloakHealthCheck>("keycloak")
        .AddCheck<RabbitMQHealthCheck>("rabbitmq");
        
    Console.WriteLine("? Services registered successfully");
}
catch (Exception ex)
{
    Console.WriteLine($"? Failed to register services: {ex.Message}");
    Console.WriteLine("?? Continuing without KeyCloak/RabbitMQ integration...");
    
    // Register minimal health checks in case of failure
    builder.Services.AddHealthChecks();
}

var app = builder.Build();

Console.WriteLine("?? Application built successfully");

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "KeyCloak RabbitMQ Demo API v1");
        c.RoutePrefix = string.Empty; // Swagger na root path
    });
    
    app.Logger.LogInformation("?? Running in Development mode");
}

app.UseAuthorization();
app.MapControllers();

// Add simple test endpoints
app.MapGet("/test", () => new { 
    message = "Application is working!", 
    timestamp = DateTime.UtcNow,
    status = "healthy"
});

app.MapGet("/ping", () => "pong");

// Try to initialize RabbitMQ topology, but don't fail if it doesn't work
try
{
    var producerService = app.Services.GetService<MessageProducerService>();
    if (producerService != null)
    {
        await producerService.InitializeTopologyAsync();
        app.Logger.LogInformation("? RabbitMQ topology initialized successfully");
    }
    else
    {
        app.Logger.LogWarning("?? MessageProducerService not available - skipping topology initialization");
    }
}
catch (Exception ex)
{
    app.Logger.LogError(ex, "? Failed to initialize RabbitMQ topology");
    app.Logger.LogWarning("?? Application will continue but RabbitMQ functionality may not be available");
}

app.Logger.LogInformation("?? KeyCloak RabbitMQ Demo Application is starting...");

// Display the URLs
var urls = app.Configuration["ASPNETCORE_URLS"] ?? "http://localhost:5156;https://localhost:7156";
var httpUrl = urls.Split(';').FirstOrDefault(u => u.StartsWith("http://")) ?? urls.Split(';')[0];

app.Logger.LogInformation("?? Test endpoints:");
app.Logger.LogInformation("   Basic test: {Url}/test", httpUrl);
app.Logger.LogInformation("   Ping test: {Url}/ping", httpUrl);
app.Logger.LogInformation("   Controller test: {Url}/api/test", httpUrl);
app.Logger.LogInformation("?? Swagger UI: {Url}", httpUrl);
app.Logger.LogInformation("?? Health checks: {Url}/api/health", httpUrl);

try
{
    app.Run();
}
catch (Exception ex)
{
    Console.WriteLine($"? Application failed to start: {ex.Message}");
    Console.WriteLine($"Stack trace: {ex.StackTrace}");
    throw;
}
