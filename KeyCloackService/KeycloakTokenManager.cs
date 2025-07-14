using System.Text.Json;
using System.Web;

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

    /// <summary>
    /// Event fired when device authorization is initiated (Device Flow)
    /// </summary>
    public event EventHandler<DeviceAuthorizationResponse>? DeviceAuthorizationStarted;

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

            // Try to refresh first if we have a refresh token (for flows that support it)
            if (_currentToken?.RefreshToken is not null && SupportsRefreshToken(_config.Flow))
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
            AuthenticationFlow.AuthorizationCode => throw new KeycloakAuthenticationException("Authorization Code flow requires manual code exchange. Use GetAuthorizationUrl() and ExchangeCodeForTokenAsync()."),
            AuthenticationFlow.AuthorizationCodePKCE => throw new KeycloakAuthenticationException("Authorization Code PKCE flow requires manual code exchange. Use GetAuthorizationUrl() and ExchangeCodeForTokenAsync()."),
            AuthenticationFlow.DeviceFlow => await AuthenticateWithDeviceFlowAsync(cancellationToken),
            _ => throw new KeycloakAuthenticationException($"Unsupported authentication flow: {_config.Flow}")
        };
    }

    /// <summary>
    /// Generates authorization URL for Authorization Code or Authorization Code PKCE flows
    /// </summary>
    public string GetAuthorizationUrl()
    {
        if (_config.Flow != AuthenticationFlow.AuthorizationCode && _config.Flow != AuthenticationFlow.AuthorizationCodePKCE)
        {
            throw new KeycloakAuthenticationException($"GetAuthorizationUrl() is only available for Authorization Code flows, current flow: {_config.Flow}");
        }

        if (string.IsNullOrEmpty(_config.RedirectUri))
        {
            throw new KeycloakAuthenticationException("RedirectUri is required for Authorization Code flows");
        }

        var authEndpoint = $"{_config.ServerUrl}/realms/{_config.Realm}/protocol/openid-connect/auth";
        var queryParams = new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = _config.ClientId,
            ["redirect_uri"] = _config.RedirectUri,
            ["scope"] = _config.Scopes ?? "openid profile email",
            ["state"] = _config.State ?? PKCEHelper.GenerateState()
        };

        // Add PKCE parameters for PKCE flow
        if (_config.Flow == AuthenticationFlow.AuthorizationCodePKCE)
        {
            var codeVerifier = _config.CodeVerifier ?? PKCEHelper.GenerateCodeVerifier();
            var codeChallenge = _config.CodeChallenge ?? PKCEHelper.GenerateCodeChallenge(codeVerifier);
            
            queryParams["code_challenge"] = codeChallenge;
            queryParams["code_challenge_method"] = _config.CodeChallengeMethod;
            
            // Store code verifier for later use (you might want to handle this differently)
            // This is a simplified approach - in real apps you'd store this securely
        }

        var queryString = string.Join("&", queryParams.Select(kvp => 
            $"{HttpUtility.UrlEncode(kvp.Key)}={HttpUtility.UrlEncode(kvp.Value)}"));

        return $"{authEndpoint}?{queryString}";
    }

    /// <summary>
    /// Exchanges authorization code for tokens (Authorization Code flows)
    /// </summary>
    public async Task<KeycloakTokenResponse> ExchangeCodeForTokenAsync(string authorizationCode, string? state = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(authorizationCode);

        if (_config.Flow != AuthenticationFlow.AuthorizationCode && _config.Flow != AuthenticationFlow.AuthorizationCodePKCE)
        {
            throw new KeycloakAuthenticationException($"Code exchange is only available for Authorization Code flows, current flow: {_config.Flow}");
        }

        if (string.IsNullOrEmpty(_config.RedirectUri))
        {
            throw new KeycloakAuthenticationException("RedirectUri is required for Authorization Code flows");
        }

        // Validate state parameter if provided
        if (!string.IsNullOrEmpty(_config.State) && !string.IsNullOrEmpty(state) && _config.State != state)
        {
            throw new KeycloakAuthenticationException("State parameter mismatch - possible CSRF attack");
        }

        var parameters = new List<KeyValuePair<string, string>>
        {
            new("grant_type", "authorization_code"),
            new("client_id", _config.ClientId),
            new("code", authorizationCode),
            new("redirect_uri", _config.RedirectUri)
        };

        // Add client secret for confidential clients
        if (!string.IsNullOrEmpty(_config.ClientSecret))
        {
            parameters.Add(new("client_secret", _config.ClientSecret));
        }

        // Add PKCE code verifier for PKCE flow
        if (_config.Flow == AuthenticationFlow.AuthorizationCodePKCE)
        {
            if (string.IsNullOrEmpty(_config.CodeVerifier))
            {
                throw new KeycloakAuthenticationException("CodeVerifier is required for Authorization Code PKCE flow");
            }
            parameters.Add(new("code_verifier", _config.CodeVerifier));
        }

        return await ExecuteTokenRequestAsync(parameters, "Authorization code exchange", cancellationToken);
    }

    /// <summary>
    /// Initiates Device Flow authentication
    /// </summary>
    public async Task<DeviceAuthorizationResponse> InitiateDeviceFlowAsync(CancellationToken cancellationToken = default)
    {
        if (_config.Flow != AuthenticationFlow.DeviceFlow)
        {
            throw new KeycloakAuthenticationException($"Device flow initiation is only available for Device Flow, current flow: {_config.Flow}");
        }

        var deviceEndpoint = $"{_config.ServerUrl}/realms/{_config.Realm}/protocol/openid-connect/auth/device";

        var parameters = new List<KeyValuePair<string, string>>
        {
            new("client_id", _config.ClientId),
            new("scope", _config.Scopes ?? "openid profile email")
        };

        if (!string.IsNullOrEmpty(_config.ClientSecret))
        {
            parameters.Add(new("client_secret", _config.ClientSecret));
        }

        var content = new FormUrlEncodedContent(parameters);

        try
        {
            var response = await _httpClient.PostAsync(deviceEndpoint, content, cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync(cancellationToken);
                throw new KeycloakAuthenticationException(
                    $"Device flow initiation failed with status {response.StatusCode}: {errorContent}");
            }

            var responseContent = await response.Content.ReadAsStringAsync(cancellationToken);
            var deviceResponse = JsonSerializer.Deserialize<DeviceAuthorizationResponse>(responseContent);

            if (deviceResponse is null)
            {
                throw new KeycloakAuthenticationException("Failed to deserialize device authorization response");
            }

            DeviceAuthorizationStarted?.Invoke(this, deviceResponse);
            return deviceResponse;
        }
        catch (HttpRequestException ex)
        {
            var authException = new KeycloakAuthenticationException($"Device flow initiation failed: {ex.Message}", ex);
            AuthenticationFailed?.Invoke(this, authException);
            throw authException;
        }
    }

    /// <summary>
    /// Polls for token completion in Device Flow
    /// </summary>
    public async Task<KeycloakTokenResponse> PollForDeviceTokenAsync(string deviceCode, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(deviceCode);

        var parameters = new List<KeyValuePair<string, string>>
        {
            new("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            new("client_id", _config.ClientId),
            new("device_code", deviceCode)
        };

        if (!string.IsNullOrEmpty(_config.ClientSecret))
        {
            parameters.Add(new("client_secret", _config.ClientSecret));
        }

        return await ExecuteTokenRequestAsync(parameters, "Device flow token polling", cancellationToken);
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
    /// Authenticates with Keycloak using Device Flow
    /// </summary>
    private async Task<KeycloakTokenResponse> AuthenticateWithDeviceFlowAsync(CancellationToken cancellationToken = default)
    {
        // Initiate device flow
        var deviceResponse = await InitiateDeviceFlowAsync(cancellationToken);

        // Continuously poll for token until success or timeout
        using var timeoutCts = new CancellationTokenSource(_config.DeviceFlowTimeout);
        using var combinedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);

        var pollingInterval = TimeSpan.FromSeconds(Math.Max(_config.DeviceFlowPollingInterval, deviceResponse.Interval));

        while (!combinedCts.Token.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(pollingInterval, combinedCts.Token);
                return await PollForDeviceTokenAsync(deviceResponse.DeviceCode, combinedCts.Token);
            }
            catch (KeycloakAuthenticationException ex) when (ex.Message.Contains("authorization_pending"))
            {
                // Continue polling
                continue;
            }
            catch (KeycloakAuthenticationException ex) when (ex.Message.Contains("slow_down"))
            {
                // Increase polling interval
                pollingInterval = pollingInterval.Add(TimeSpan.FromSeconds(5));
                continue;
            }
            catch (OperationCanceledException) when (timeoutCts.Token.IsCancellationRequested)
            {
                throw new KeycloakAuthenticationException("Device flow authentication timed out");
            }
        }

        throw new KeycloakAuthenticationException("Device flow authentication was cancelled");
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

            // Update internal token cache - NO SEMAPHORE HERE as caller already holds it
            _currentToken = tokenResponse;
            _tokenExpiryTime = DateTimeOffset.UtcNow.AddSeconds(tokenResponse.ExpiresIn);

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
    /// Refreshes access token using refresh token (available for flows that support refresh tokens)
    /// </summary>
    public async Task<KeycloakTokenResponse> RefreshTokenAsync(string refreshToken, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(refreshToken);

        if (!SupportsRefreshToken(_config.Flow))
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
    /// Logs out user and invalidates tokens (for flows that support logout)
    /// </summary>
    public async Task LogoutAsync(string? refreshToken = null, CancellationToken cancellationToken = default)
    {
        if (!SupportsLogout(_config.Flow))
        {
            // For flows that don't support logout, just clear local tokens
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

    /// <summary>
    /// Checks if the given flow supports refresh tokens
    /// </summary>
    private static bool SupportsRefreshToken(AuthenticationFlow flow)
    {
        return flow switch
        {
            AuthenticationFlow.Password => true,
            AuthenticationFlow.AuthorizationCode => true,
            AuthenticationFlow.AuthorizationCodePKCE => true,
            AuthenticationFlow.DeviceFlow => true,
            AuthenticationFlow.ClientCredentials => false,
            _ => false
        };
    }

    /// <summary>
    /// Checks if the given flow supports logout
    /// </summary>
    private static bool SupportsLogout(AuthenticationFlow flow)
    {
        return flow switch
        {
            AuthenticationFlow.Password => true,
            AuthenticationFlow.AuthorizationCode => true,
            AuthenticationFlow.AuthorizationCodePKCE => true,
            AuthenticationFlow.DeviceFlow => true,
            AuthenticationFlow.ClientCredentials => false,
            _ => false
        };
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
                
            case AuthenticationFlow.AuthorizationCode:
            case AuthenticationFlow.AuthorizationCodePKCE:
                if (string.IsNullOrEmpty(_config.RedirectUri))
                {
                    throw new ArgumentException($"RedirectUri is required for {_config.Flow} flow", nameof(_config.RedirectUri));
                }
                
                if (_config.Flow == AuthenticationFlow.AuthorizationCodePKCE && string.IsNullOrEmpty(_config.CodeVerifier))
                {
                    // Auto-generate if not provided
                    // Note: In a real implementation, you'd want to store this more securely
                }
                break;
                
            case AuthenticationFlow.DeviceFlow:
                // No specific validation required
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