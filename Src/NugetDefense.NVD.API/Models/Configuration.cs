using System.Text.Json.Serialization;

namespace NugetDefense.NVD.API;

public class Configuration
{
    [JsonPropertyName("nodes")] public Node[]? Nodes { get; set; }
}