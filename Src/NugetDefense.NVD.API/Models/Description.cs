using System.Text.Json.Serialization;

namespace NugetDefense.NVD.API;

public class Description
{
    [JsonPropertyName("lang")] public string Lang { get; set; }

    [JsonPropertyName("value")] public string Value { get; set; }
}