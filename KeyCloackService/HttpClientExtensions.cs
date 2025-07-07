using System.Net.Http.Headers;

namespace KeyCloackService;

/// <summary>
/// Extension methods for HttpClient to work with Keycloak tokens
/// </summary>
public static class HttpClientExtensions
{
    /// <summary>
    /// Sets Bearer token in Authorization header
    /// </summary>
    public static void SetBearerToken(this HttpClient httpClient, string token)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentException.ThrowIfNullOrEmpty(token);
        
        httpClient.DefaultRequestHeaders.Authorization = 
            new AuthenticationHeaderValue("Bearer", token);
    }

    /// <summary>
    /// Removes Authorization header
    /// </summary>
    public static void ClearBearerToken(this HttpClient httpClient)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        httpClient.DefaultRequestHeaders.Authorization = null;
    }

    /// <summary>
    /// Sets Bearer token using KeycloakTokenManager
    /// </summary>
    public static async Task SetBearerTokenAsync(this HttpClient httpClient, KeycloakTokenManager tokenManager, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(tokenManager);
        
        var token = await tokenManager.GetAccessTokenAsync(cancellationToken);
        httpClient.SetBearerToken(token);
    }
}