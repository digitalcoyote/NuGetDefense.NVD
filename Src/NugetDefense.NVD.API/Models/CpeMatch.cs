using System.Text.Json.Serialization;

namespace NugetDefense.NVD.API;

public class CpeMatch
{
    [JsonPropertyName("vulnerable")] public bool Vulnerable { get; set; }

    [JsonPropertyName("criteria")] public string Criteria { get; set; }

    [JsonPropertyName("matchCriteriaId")] public string MatchCriteriaId { get; set; }

    [JsonPropertyName("versionStartIncluding")]
    public string? VersionStartIncluding { get; set; }

    [JsonPropertyName("versionEndIncluding")]
    public string? VersionEndIncluding { get; set; }

    [JsonPropertyName("versionEndExcluding")]
    public string? VersionEndExcluding { get; set; }
}