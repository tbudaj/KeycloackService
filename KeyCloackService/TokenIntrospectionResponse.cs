using System.Text.Json.Serialization;

namespace KeyCloackService;

/// <summary>
/// Represents token introspection response
/// </summary>
public class TokenIntrospectionResponse
{
    [JsonPropertyName("active")]
    public bool Active { get; set; }

    [JsonPropertyName("exp")]
    public long? Exp { get; set; }

    [JsonPropertyName("iat")]
    public long? Iat { get; set; }

    [JsonPropertyName("sub")]
    public string? Subject { get; set; }

    [JsonPropertyName("username")]
    public string? Username { get; set; }

    [JsonPropertyName("client_id")]
    public string? ClientId { get; set; }

    [JsonPropertyName("scope")]
    public string? Scope { get; set; }
}