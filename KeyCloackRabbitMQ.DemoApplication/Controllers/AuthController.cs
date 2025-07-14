using Microsoft.AspNetCore.Mvc;
using KeyCloackRabbitMQ.DemoApplication.Models;
using KeyCloackService;
using System.Text.Json;

namespace KeyCloackRabbitMQ.DemoApplication.Controllers;

/// <summary>
/// Controller for JWT token operations and authentication
/// </summary>
[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<AuthController> _logger;
    private readonly HttpClient _httpClient;

    public AuthController(IConfiguration configuration, ILogger<AuthController> logger, HttpClient httpClient)
    {
        _configuration = configuration;
        _logger = logger;
        _httpClient = httpClient;
    }

    /// <summary>
    /// Get JWT token for client application authentication
    /// </summary>
    [HttpPost("token")]
    public async Task<ActionResult<ApiResponse<object>>> GetToken([FromBody] TokenRequest request)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
            {
                return BadRequest(ApiResponse<object>.ErrorResponse("Username and password are required"));
            }

            var keycloakConfig = _configuration.GetSection("Keycloak");
            var serverUrl = keycloakConfig["ServerUrl"];
            var realm = keycloakConfig["Realm"];
            var clientId = keycloakConfig["ClientId"];
            var clientSecret = keycloakConfig["ClientSecret"];

            // Create token request to Keycloak
            var tokenEndpoint = $"{serverUrl}/realms/{realm}/protocol/openid-connect/token";
            
            var tokenRequestBody = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("grant_type", "password"),
                new KeyValuePair<string, string>("client_id", clientId!),
                new KeyValuePair<string, string>("client_secret", clientSecret!),
                new KeyValuePair<string, string>("username", request.Username),
                new KeyValuePair<string, string>("password", request.Password),
                new KeyValuePair<string, string>("scope", "openid profile email")
            });

            var response = await _httpClient.PostAsync(tokenEndpoint, tokenRequestBody);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("?? Token request failed for user {Username}: {Status} - {Response}", 
                    request.Username, response.StatusCode, responseContent);
                
                return Unauthorized(ApiResponse<object>.ErrorResponse("Invalid username or password"));
            }

            var tokenResponse = JsonSerializer.Deserialize<JsonElement>(responseContent);
            
            var result = new
            {
                AccessToken = tokenResponse.GetProperty("access_token").GetString(),
                TokenType = tokenResponse.GetProperty("token_type").GetString(),
                ExpiresIn = tokenResponse.GetProperty("expires_in").GetInt32(),
                RefreshToken = tokenResponse.TryGetProperty("refresh_token", out var refreshProp) ? refreshProp.GetString() : null,
                Scope = tokenResponse.TryGetProperty("scope", out var scopeProp) ? scopeProp.GetString() : null,
                IssuedAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(tokenResponse.GetProperty("expires_in").GetInt32())
            };

            _logger.LogInformation("?? JWT token issued successfully for user {Username}", request.Username);

            return Ok(ApiResponse<object>.SuccessResponse(result, "Token retrieved successfully"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get JWT token for user {Username}", request.Username);
            return StatusCode(500, ApiResponse<object>.ErrorResponse($"Failed to get token: {ex.Message}"));
        }
    }

    /// <summary>
    /// Refresh JWT token using refresh token
    /// </summary>
    [HttpPost("refresh")]
    public async Task<ActionResult<ApiResponse<object>>> RefreshToken([FromBody] RefreshTokenRequest request)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(request.RefreshToken))
            {
                return BadRequest(ApiResponse<object>.ErrorResponse("Refresh token is required"));
            }

            var keycloakConfig = _configuration.GetSection("Keycloak");
            var serverUrl = keycloakConfig["ServerUrl"];
            var realm = keycloakConfig["Realm"];
            var clientId = keycloakConfig["ClientId"];
            var clientSecret = keycloakConfig["ClientSecret"];

            var tokenEndpoint = $"{serverUrl}/realms/{realm}/protocol/openid-connect/token";
            
            var tokenRequestBody = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("grant_type", "refresh_token"),
                new KeyValuePair<string, string>("client_id", clientId!),
                new KeyValuePair<string, string>("client_secret", clientSecret!),
                new KeyValuePair<string, string>("refresh_token", request.RefreshToken)
            });

            var response = await _httpClient.PostAsync(tokenEndpoint, tokenRequestBody);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("?? Token refresh failed: {Status} - {Response}", 
                    response.StatusCode, responseContent);
                
                return Unauthorized(ApiResponse<object>.ErrorResponse("Invalid refresh token"));
            }

            var tokenResponse = JsonSerializer.Deserialize<JsonElement>(responseContent);
            
            var result = new
            {
                AccessToken = tokenResponse.GetProperty("access_token").GetString(),
                TokenType = tokenResponse.GetProperty("token_type").GetString(),
                ExpiresIn = tokenResponse.GetProperty("expires_in").GetInt32(),
                RefreshToken = tokenResponse.TryGetProperty("refresh_token", out var refreshProp) ? refreshProp.GetString() : request.RefreshToken,
                Scope = tokenResponse.TryGetProperty("scope", out var scopeProp) ? scopeProp.GetString() : null,
                IssuedAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(tokenResponse.GetProperty("expires_in").GetInt32())
            };

            _logger.LogInformation("?? JWT token refreshed successfully");

            return Ok(ApiResponse<object>.SuccessResponse(result, "Token refreshed successfully"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to refresh JWT token");
            return StatusCode(500, ApiResponse<object>.ErrorResponse($"Failed to refresh token: {ex.Message}"));
        }
    }

    /// <summary>
    /// Get Keycloak server information and endpoints
    /// </summary>
    [HttpGet("info")]
    public ActionResult<ApiResponse<object>> GetAuthInfo()
    {
        try
        {
            var keycloakConfig = _configuration.GetSection("Keycloak");
            var jwtConfig = _configuration.GetSection("JwtAuthentication");
            
            var authInfo = new
            {
                KeycloakServer = keycloakConfig["ServerUrl"],
                Realm = keycloakConfig["Realm"],
                ClientId = keycloakConfig["ClientId"],
                Authority = jwtConfig["Authority"],
                TokenEndpoint = $"{keycloakConfig["ServerUrl"]}/realms/{keycloakConfig["Realm"]}/protocol/openid-connect/token",
                AuthEndpoint = $"{keycloakConfig["ServerUrl"]}/realms/{keycloakConfig["Realm"]}/protocol/openid-connect/auth",
                UserInfoEndpoint = $"{keycloakConfig["ServerUrl"]}/realms/{keycloakConfig["Realm"]}/protocol/openid-connect/userinfo",
                JwksEndpoint = $"{keycloakConfig["ServerUrl"]}/realms/{keycloakConfig["Realm"]}/protocol/openid-connect/certs",
                SupportedGrantTypes = new[] { "password", "authorization_code", "client_credentials", "refresh_token" },
                RequireHttpsMetadata = jwtConfig.GetValue<bool>("RequireHttpsMetadata")
            };

            return Ok(ApiResponse<object>.SuccessResponse(authInfo, "Auth information retrieved successfully"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get auth info");
            return StatusCode(500, ApiResponse<object>.ErrorResponse($"Failed to get auth info: {ex.Message}"));
        }
    }
}