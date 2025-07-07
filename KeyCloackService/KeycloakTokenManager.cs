using System.Text.Json;

namespace KeyCloackService;

/// <summary>
/// Main class for managing Keycloak tokens with automatic refresh
/// </summary>
public class KeycloakTokenManager : IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly KeycloakConfig _config;
    private readonly bool _ownsHttpClient;
    private KeycloakTokenResponse? _currentToken;
    private DateTimeOffset _tokenExpiryTime;
    private readonly SemaphoreSlim _semaphore = new(1, 1);

    /// <summary>
    /// Event fired when token is refreshed
    /// </summary>
    public event EventHandler<KeycloakTokenResponse>? TokenRefreshed;

    /// <summary>
    /// Event fired when authentication fails
    /// </summary>
    public event EventHandler<KeycloakAuthenticationException>? AuthenticationFailed;

    public KeycloakTokenManager(KeycloakConfig config, HttpClient? httpClient = null)
    {
        ArgumentNullException.ThrowIfNull(config);
        
        _config = config;
        _httpClient = httpClient ?? new HttpClient();
        _ownsHttpClient = httpClient is null;
        
        ValidateConfig();
    }

    /// <summary>
    /// Gets valid access token, automatically refreshing if needed
    /// </summary>
    public async Task<string> GetAccessTokenAsync(CancellationToken cancellationToken = default)
    {
        await _semaphore.WaitAsync(cancellationToken);
        try
        {
            var buffer = _config.TokenRefreshBuffer ?? TimeSpan.FromMinutes(5);
            
            // Check if current token is still valid (with buffer)
            if (_currentToken is not null && DateTimeOffset.UtcNow < _tokenExpiryTime.Subtract(buffer))
            {
                return _currentToken.AccessToken;
            }

            // Try to refresh first if we have a refresh token (only for Password flow)
            if (_currentToken?.RefreshToken is not null && _config.Flow == AuthenticationFlow.Password)
            {
                try
                {
                    var refreshedToken = await RefreshTokenAsync(_currentToken.RefreshToken, cancellationToken);
                    return refreshedToken.AccessToken;
                }
                catch (KeycloakAuthenticationException)
                {
                    // Refresh failed, fall back to authentication
                    _currentToken = null;
                }
            }

            // Token expired or doesn't exist, get new one using configured flow
            var token = await AuthenticateAsync(cancellationToken);
            return token.AccessToken;
        }
        finally
        {
            _semaphore.Release();
        }
    }

    /// <summary>
    /// Authenticates with Keycloak using the configured authentication flow
    /// </summary>
    public async Task<KeycloakTokenResponse> AuthenticateAsync(CancellationToken cancellationToken = default)
    {
        return _config.Flow switch
        {
            AuthenticationFlow.Password => await AuthenticateWithPasswordAsync(cancellationToken),
            AuthenticationFlow.ClientCredentials => await AuthenticateWithClientCredentialsAsync(cancellationToken),
            _ => throw new KeycloakAuthenticationException($"Unsupported authentication flow: {_config.Flow}")
        };
    }

    /// <summary>
    /// Authenticates with Keycloak using username/password flow
    /// </summary>
    private async Task<KeycloakTokenResponse> AuthenticateWithPasswordAsync(CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(_config.Username) || string.IsNullOrEmpty(_config.Password))
        {
            throw new KeycloakAuthenticationException("Username and password are required for password flow authentication");
        }

        var tokenEndpoint = $"{_config.ServerUrl}/realms/{_config.Realm}/protocol/openid-connect/token";

        var parameters = new List<KeyValuePair<string, string>>
        {
            new("grant_type", "password"),
            new("client_id", _config.ClientId),
            new("username", _config.Username),
            new("password", _config.Password)
        };

        // Add client secret if provided (for confidential clients)
        if (!string.IsNullOrEmpty(_config.ClientSecret))
        {
            parameters.Add(new("client_secret", _config.ClientSecret));
        }

        return await ExecuteTokenRequestAsync(parameters, "Password flow authentication", cancellationToken);
    }

    /// <summary>
    /// Authenticates with Keycloak using client credentials flow
    /// </summary>
    private async Task<KeycloakTokenResponse> AuthenticateWithClientCredentialsAsync(CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(_config.ClientSecret))
        {
            throw new KeycloakAuthenticationException("ClientSecret is required for client credentials flow authentication");
        }

        var parameters = new List<KeyValuePair<string, string>>
        {
            new("grant_type", "client_credentials"),
            new("client_id", _config.ClientId),
            new("client_secret", _config.ClientSecret)
        };

        return await ExecuteTokenRequestAsync(parameters, "Client credentials flow authentication", cancellationToken);
    }

    /// <summary>
    /// Executes token request with common error handling and caching logic
    /// </summary>
    private async Task<KeycloakTokenResponse> ExecuteTokenRequestAsync(
        List<KeyValuePair<string, string>> parameters,
        string operationName,
        CancellationToken cancellationToken)
    {
        var tokenEndpoint = $"{_config.ServerUrl}/realms/{_config.Realm}/protocol/openid-connect/token";
        var content = new FormUrlEncodedContent(parameters);

        try
        {
            var response = await _httpClient.PostAsync(tokenEndpoint, content, cancellationToken);
            
            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync(cancellationToken);
                throw new KeycloakAuthenticationException(
                    $"{operationName} failed with status {response.StatusCode}: {errorContent}");
            }

            var responseContent = await response.Content.ReadAsStringAsync(cancellationToken);
            var tokenResponse = JsonSerializer.Deserialize<KeycloakTokenResponse>(responseContent);

            if (tokenResponse is null)
            {
                throw new KeycloakAuthenticationException($"Failed to deserialize {operationName.ToLower()} response");
            }

            // Update internal token cache
            await _semaphore.WaitAsync(cancellationToken);
            try
            {
                _currentToken = tokenResponse;
                _tokenExpiryTime = DateTimeOffset.UtcNow.AddSeconds(tokenResponse.ExpiresIn);
            }
            finally
            {
                _semaphore.Release();
            }

            TokenRefreshed?.Invoke(this, tokenResponse);
            return tokenResponse;
        }
        catch (HttpRequestException ex)
        {
            var authException = new KeycloakAuthenticationException($"{operationName} failed: {ex.Message}", ex);
            AuthenticationFailed?.Invoke(this, authException);
            throw authException;
        }
        catch (JsonException ex)
        {
            var authException = new KeycloakAuthenticationException($"Failed to parse {operationName.ToLower()} response: {ex.Message}", ex);
            AuthenticationFailed?.Invoke(this, authException);
            throw authException;
        }
    }

    /// <summary>
    /// Refreshes access token using refresh token (only available for Password flow)
    /// </summary>
    public async Task<KeycloakTokenResponse> RefreshTokenAsync(string refreshToken, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(refreshToken);

        if (_config.Flow != AuthenticationFlow.Password)
        {
            throw new KeycloakAuthenticationException($"Token refresh is not available for {_config.Flow} flow");
        }

        var parameters = new List<KeyValuePair<string, string>>
        {
            new("grant_type", "refresh_token"),
            new("client_id", _config.ClientId),
            new("refresh_token", refreshToken)
        };

        if (!string.IsNullOrEmpty(_config.ClientSecret))
        {
            parameters.Add(new("client_secret", _config.ClientSecret));
        }

        return await ExecuteTokenRequestAsync(parameters, "Token refresh", cancellationToken);
    }

    /// <summary>
    /// Validates if token is still active using Keycloak introspection endpoint
    /// </summary>
    public async Task<TokenIntrospectionResponse> IntrospectTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(token);

        var introspectEndpoint = $"{_config.ServerUrl}/realms/{_config.Realm}/protocol/openid-connect/token/introspect";

        var parameters = new List<KeyValuePair<string, string>>
        {
            new("token", token),
            new("client_id", _config.ClientId)
        };

        if (!string.IsNullOrEmpty(_config.ClientSecret))
        {
            parameters.Add(new("client_secret", _config.ClientSecret));
        }

        var content = new FormUrlEncodedContent(parameters);

        try
        {
            var response = await _httpClient.PostAsync(introspectEndpoint, content, cancellationToken);
            response.EnsureSuccessStatusCode();

            var responseContent = await response.Content.ReadAsStringAsync(cancellationToken);
            var introspectResponse = JsonSerializer.Deserialize<TokenIntrospectionResponse>(responseContent);

            return introspectResponse ?? new TokenIntrospectionResponse { Active = false };
        }
        catch (Exception ex)
        {
            throw new KeycloakAuthenticationException($"Token introspection failed: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Simple validation that only checks if token is active
    /// </summary>
    public async Task<bool> ValidateTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        try
        {
            var result = await IntrospectTokenAsync(token, cancellationToken);
            return result.Active;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Logs out user and invalidates tokens (for Password flow only)
    /// </summary>
    public async Task LogoutAsync(string? refreshToken = null, CancellationToken cancellationToken = default)
    {
        if (_config.Flow != AuthenticationFlow.Password)
        {
            // For Client Credentials flow, just clear local tokens
            ClearTokens();
            return;
        }

        var tokenToUse = refreshToken ?? _currentToken?.RefreshToken;
        
        if (string.IsNullOrEmpty(tokenToUse))
        {
            ClearTokens();
            return;
        }

        var logoutEndpoint = $"{_config.ServerUrl}/realms/{_config.Realm}/protocol/openid-connect/logout";

        var parameters = new List<KeyValuePair<string, string>>
        {
            new("client_id", _config.ClientId),
            new("refresh_token", tokenToUse)
        };

        if (!string.IsNullOrEmpty(_config.ClientSecret))
        {
            parameters.Add(new("client_secret", _config.ClientSecret));
        }

        var content = new FormUrlEncodedContent(parameters);

        try
        {
            var response = await _httpClient.PostAsync(logoutEndpoint, content, cancellationToken);
            response.EnsureSuccessStatusCode();
        }
        catch (HttpRequestException ex)
        {
            throw new KeycloakAuthenticationException($"Logout failed: {ex.Message}", ex);
        }
        finally
        {
            // Clear cached tokens regardless of success/failure
            ClearTokens();
        }
    }

    /// <summary>
    /// Clears cached tokens from memory
    /// </summary>
    public void ClearTokens()
    {
        _semaphore.Wait();
        try
        {
            _currentToken = null;
            _tokenExpiryTime = DateTimeOffset.MinValue;
        }
        finally
        {
            _semaphore.Release();
        }
    }

    /// <summary>
    /// Gets current token information without triggering refresh
    /// </summary>
    public KeycloakTokenResponse? GetCurrentToken()
    {
        _semaphore.Wait();
        try
        {
            return _currentToken;
        }
        finally
        {
            _semaphore.Release();
        }
    }

    /// <summary>
    /// Checks if current token is expired
    /// </summary>
    public bool IsTokenExpired()
    {
        _semaphore.Wait();
        try
        {
            return _currentToken is null || DateTimeOffset.UtcNow >= _tokenExpiryTime;
        }
        finally
        {
            _semaphore.Release();
        }
    }

    /// <summary>
    /// Gets time until token expires
    /// </summary>
    public TimeSpan? GetTimeUntilExpiry()
    {
        _semaphore.Wait();
        try
        {
            if (_currentToken is null) return null;
            
            var remaining = _tokenExpiryTime - DateTimeOffset.UtcNow;
            return remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero;
        }
        finally
        {
            _semaphore.Release();
        }
    }

    private void ValidateConfig()
    {
        ArgumentException.ThrowIfNullOrEmpty(_config.ServerUrl, nameof(_config.ServerUrl));
        ArgumentException.ThrowIfNullOrEmpty(_config.Realm, nameof(_config.Realm));
        ArgumentException.ThrowIfNullOrEmpty(_config.ClientId, nameof(_config.ClientId));
        
        if (!Uri.TryCreate(_config.ServerUrl, UriKind.Absolute, out _))
        {
            throw new ArgumentException("ServerUrl must be a valid absolute URI", nameof(_config.ServerUrl));
        }

        // Validate flow-specific requirements
        switch (_config.Flow)
        {
            case AuthenticationFlow.Password:
                // Username and password will be validated at authentication time
                break;
                
            case AuthenticationFlow.ClientCredentials:
                if (string.IsNullOrEmpty(_config.ClientSecret))
                {
                    throw new ArgumentException("ClientSecret is required for ClientCredentials flow", nameof(_config.ClientSecret));
                }
                break;
                
            default:
                throw new ArgumentException($"Unsupported authentication flow: {_config.Flow}", nameof(_config.Flow));
        }
    }

    public void Dispose()
    {
        _semaphore.Dispose();
        
        if (_ownsHttpClient)
        {
            _httpClient.Dispose();
        }
    }
}