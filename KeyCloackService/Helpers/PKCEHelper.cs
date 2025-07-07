namespace KeyCloackService;

/// <summary>
/// Helper class for PKCE (Proof Key for Code Exchange) implementation
/// </summary>
public static class PKCEHelper
{
    /// <summary>
    /// Generates a random code verifier for PKCE
    /// </summary>
    public static string GenerateCodeVerifier()
    {
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
        var random = new Random();
        var length = random.Next(43, 128); // RFC 7636: length between 43-128 characters
        
        return new string(Enumerable.Repeat(chars, length)
            .Select(s => s[random.Next(s.Length)]).ToArray());
    }

    /// <summary>
    /// Generates a code challenge from code verifier using SHA256
    /// </summary>
    public static string GenerateCodeChallenge(string codeVerifier)
    {
        using var sha256 = System.Security.Cryptography.SHA256.Create();
        var challengeBytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(codeVerifier));
        return Convert.ToBase64String(challengeBytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    /// <summary>
    /// Generates a random state parameter for OAuth2 flows
    /// </summary>
    public static string GenerateState()
    {
        var bytes = new byte[32];
        using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
        rng.GetBytes(bytes);
        return Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }
}