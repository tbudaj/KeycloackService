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
    ClientCredentials
}