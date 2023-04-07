using System.Text.Json.Serialization;

namespace NugetDefense.NVD.API;

public class CvssMetricV2
{
    [JsonPropertyName("source")] public string? Source { get; set; }

    [JsonPropertyName("type")] public string? Type { get; set; }

    [JsonPropertyName("cvssData")] public CvssData? CvssData { get; set; }

    [JsonPropertyName("baseSeverity")] public string? BaseSeverity { get; set; }

    [JsonPropertyName("exploitabilityScore")]
    public long ExploitabilityScore { get; set; }

    [JsonPropertyName("impactScore")] public long ImpactScore { get; set; }

    [JsonPropertyName("acInsufInfo")] public bool AcInsufInfo { get; set; }

    [JsonPropertyName("obtainAllPrivilege")]
    public bool ObtainAllPrivilege { get; set; }

    [JsonPropertyName("obtainUserPrivilege")]
    public bool ObtainUserPrivilege { get; set; }

    [JsonPropertyName("obtainOtherPrivilege")]
    public bool ObtainOtherPrivilege { get; set; }

    [JsonPropertyName("userInteractionRequired")]
    public bool UserInteractionRequired { get; set; }
}