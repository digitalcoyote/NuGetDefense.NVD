using System.Text.Json.Serialization;

namespace NugetDefense.NVD.API;

public class VendorComment
{
    [JsonPropertyName("organization")] public string? Organization { get; set; }

    [JsonPropertyName("comment")] public string? Comment { get; set; }

    [JsonPropertyName("lastModified")] public DateTimeOffset LastModified { get; set; }
}