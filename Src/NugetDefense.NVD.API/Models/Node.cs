using System.Text.Json.Serialization;

namespace NugetDefense.NVD.API;

public class Node
{
    [JsonPropertyName("operator")] public string? Operator { get; set; }

    [JsonPropertyName("negate")] public bool Negate { get; set; }

    /// <summary>
    /// Contains the CPE Match Criteria, the criteria's unique identifier,
    /// and a statement of whether the criteria is vulnerable.
    /// </summary>
    [JsonPropertyName("cpeMatch")] public CpeMatch[]? CpeMatch { get; set; }
}