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
    
    // Authorization Code Flow properties
    /// <summary>
    /// Redirect URI for Authorization Code Flow
    /// </summary>
    public string? RedirectUri { get; init; }
    
    /// <summary>
    /// Scopes to request (space-separated string)
    /// </summary>
    public string? Scopes { get; init; } = "openid profile email";
    
    /// <summary>
    /// State parameter for OAuth2 flows (auto-generated if not provided)
    /// </summary>
    public string? State { get; init; }
    
    // PKCE properties
    /// <summary>
    /// Code verifier for PKCE (auto-generated if not provided)
    /// </summary>
    public string? CodeVerifier { get; init; }
    
    /// <summary>
    /// Code challenge for PKCE (auto-generated from CodeVerifier if not provided)
    /// </summary>
    public string? CodeChallenge { get; init; }
    
    /// <summary>
    /// Code challenge method for PKCE (default: S256)
    /// </summary>
    public string CodeChallengeMethod { get; init; } = "S256";
    
    // Device Flow properties
    /// <summary>
    /// Polling interval for Device Flow (in seconds, default: 5)
    /// </summary>
    public int DeviceFlowPollingInterval { get; init; } = 5;
    
    /// <summary>
    /// Maximum polling duration for Device Flow (default: 10 minutes)
    /// </summary>
    public TimeSpan DeviceFlowTimeout { get; init; } = TimeSpan.FromMinutes(10);
}