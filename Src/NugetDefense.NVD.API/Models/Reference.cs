using System.Text.Json.Serialization;

namespace NugetDefense.NVD.API;

public class Reference
{
    [JsonPropertyName("url")] public Uri? Url { get; set; }

    /// <summary>
    /// Identifies the organization that provided the reference information.
    /// </summary>
    [JsonPropertyName("source")] public string? Source { get; set; }
}