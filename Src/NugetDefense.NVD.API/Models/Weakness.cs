using System.Text.Json.Serialization;

namespace NugetDefense.NVD.API;

public class Weakness
{
    [JsonPropertyName("source")] public string? Source { get; set; }

    [JsonPropertyName("type")] public string? Type { get; set; }

    [JsonPropertyName("description")] public Description[]? Descriptions { get; set; }
}