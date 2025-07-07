namespace KeyCloackService;

/// <summary>
/// Custom exception for Keycloak authentication errors
/// </summary>
public class KeycloakAuthenticationException : Exception
{
    public KeycloakAuthenticationException(string message) : base(message) { }
    public KeycloakAuthenticationException(string message, Exception innerException) : base(message, innerException) { }
}