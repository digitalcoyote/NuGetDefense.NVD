using System.Text.Json.Serialization;

namespace NugetDefense.NVD.API;

public class MetricsClass
{
    [JsonPropertyName("cvssMetricV2")] public CvssMetricV2[]? CvssMetricV2 { get; set; }
    [JsonPropertyName("cvssMetricV30")] public CvssMetricV3[]? CvssMetricV3 { get; set; }
}