using System.Text.Json.Serialization;

namespace NugetDefense.NVD.API;

public class CvssDataV2
{
    [JsonPropertyName("version")] public string? Version { get; set; }

    [JsonPropertyName("vectorString")] public string? VectorString { get; set; }

    [JsonPropertyName("accessVector")] public string? AccessVector { get; set; }

    [JsonPropertyName("accessComplexity")] public string? AccessComplexity { get; set; }

    [JsonPropertyName("authentication")] public string? Authentication { get; set; }

    [JsonPropertyName("confidentialityImpact")]
    public string? ConfidentialityImpact { get; set; }

    [JsonPropertyName("integrityImpact")] public string? IntegrityImpact { get; set; }

    [JsonPropertyName("availabilityImpact")]
    public string? AvailabilityImpact { get; set; }

    [JsonPropertyName("baseScore")] public double BaseScore { get; set; }
}

public class CvssDataV3
{
    [JsonPropertyName("version")] public string? Version { get; set; }

    [JsonPropertyName("vectorString")] public string? VectorString { get; set; }

    [JsonPropertyName("attackVector")] public string? AttachVector { get; set; }

    [JsonPropertyName("attackComplexity")] public string? AttackComplexity { get; set; }

    [JsonPropertyName("privilegesRequired")]
    public string? PrivilegeRequired { get; set; }

    [JsonPropertyName("userInteraction")] public string? UserInteraction { get; set; }
    [JsonPropertyName("scope")] public string? Scope { get; set; }

    [JsonPropertyName("confidentialityImpact")]
    public string? ConfidentialityImpact { get; set; }

    [JsonPropertyName("integrityImpact")] public string? IntegrityImpact { get; set; }

    [JsonPropertyName("availabilityImpact")]
    public string? AvailabilityImpact { get; set; }

    [JsonPropertyName("baseScore")] public double BaseScore { get; set; }
    [JsonPropertyName("baseSeverity")] public string BaseSeverity { get; set; }
}