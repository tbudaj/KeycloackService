using KeyCloackService.Extensions;
using KeyCloackService.MassTransit;
using KeyCloackRabbitMQ.DemoApplication.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

Console.WriteLine("?? Building application...");

// Add services to the container
builder.Services.AddControllers();

// Add Swagger/OpenAPI with JWT support
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new() { 
        Title = "KeyCloak RabbitMQ Demo API", 
        Version = "v1",
        Description = "Demo application showcasing KeyCloak Service with RabbitMQ integration and JWT authentication"
    });
    
    // Add JWT authentication to Swagger
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\"",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });
    
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

// Add logging first
builder.Logging.AddConsole();
builder.Logging.SetMinimumLevel(LogLevel.Information);

// Add HttpClient for auth operations
builder.Services.AddHttpClient();

// Configure JWT Authentication
var jwtSection = builder.Configuration.GetSection("JwtAuthentication");
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = jwtSection["Authority"];
        options.Audience = jwtSection["Audience"];
        options.RequireHttpsMetadata = jwtSection.GetValue<bool>("RequireHttpsMetadata");
        
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = jwtSection.GetValue<bool>("ValidateIssuer"),
            ValidateAudience = jwtSection.GetValue<bool>("ValidateAudience"),
            ValidateLifetime = jwtSection.GetValue<bool>("ValidateLifetime"),
            ClockSkew = TimeSpan.Parse(jwtSection["ClockSkew"] ?? "00:05:00"),
            RoleClaimType = "realm_access.roles"
        };
        
        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = context =>
            {
                Console.WriteLine($"? JWT Authentication failed: {context.Exception.Message}");
                return Task.CompletedTask;
            },
            OnTokenValidated = context =>
            {
                Console.WriteLine($"? JWT Token validated for user: {context.Principal?.Identity?.Name ?? "Unknown"}");
                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization();

try
{
    Console.WriteLine("?? Registering KeyCloak and RabbitMQ services...");
    
    // Add KeyCloak and RabbitMQ services with error handling
    builder.Services.AddKeycloakRabbitMQ();
    
    // ?? Add MassTransit support for Keycloak
    builder.Services.AddKeycloakMassTransit();
    
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

Console.WriteLine("??? Application built successfully");

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

// Add authentication and authorization middleware
app.UseAuthentication();
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
app.Logger.LogInformation("?? Secured endpoints: {Url}/api/secure-messages/*", httpUrl);
app.Logger.LogInformation("?? MassTransit demo: {Url}/api/masstransit-demo/*", httpUrl);

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
