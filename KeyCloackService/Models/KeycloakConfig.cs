namespace KeyCloackService;

/// <summary>
/// Configuration settings for Keycloak connection
/// </summary>
public record KeycloakConfig
{
    public required string ServerUrl { get; init; }
    public required string Realm { get; init; }
    public required string ClientId { get; init; }
    public string? ClientSecret { get; init; }
    public string? Username { get; init; }
    public string? Password { get; init; }
    public TimeSpan? TokenRefreshBuffer { get; init; } = TimeSpan.FromMinutes(5);
    
    /// <summary>
    /// Authentication flow to use. Defaults to Password flow for backward compatibility.
    /// </summary>
    public AuthenticationFlow Flow { get; init; } = AuthenticationFlow.Password;
}