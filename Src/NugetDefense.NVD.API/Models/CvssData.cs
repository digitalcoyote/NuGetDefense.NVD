using System.Text.Json.Serialization;

namespace NugetDefense.NVD.API;

public class CvssData
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

    [JsonPropertyName("baseScore")] public long BaseScore { get; set; }
}