namespace KeyCloackService;

/// <summary>
/// Supported authentication flows in Keycloak
/// </summary>
public enum AuthenticationFlow
{
    /// <summary>
    /// Resource Owner Password Credentials Grant - requires username and password
    /// </summary>
    Password,
    
    /// <summary>
    /// Client Credentials Grant - requires only client secret, no user credentials
    /// </summary>
    ClientCredentials,
    
    /// <summary>
    /// Authorization Code Grant - requires redirect URI and user browser interaction
    /// </summary>
    AuthorizationCode,
    
    /// <summary>
    /// Authorization Code Grant with PKCE - for public clients (mobile/SPA)
    /// </summary>
    AuthorizationCodePKCE,
    
    /// <summary>
    /// Device Flow - for devices with limited input capabilities
    /// </summary>
    DeviceFlow
}