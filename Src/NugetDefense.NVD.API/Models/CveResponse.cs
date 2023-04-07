using System.Text.Json.Serialization;

namespace NugetDefense.NVD.API;

public class CveResponse
{
    
    /// <summary>
    /// If the value of <see cref="TotalResults"/> is greater than the value of resultsPerPage, then additional requests are necessary to return the remaining CVE
    /// </summary>
    [JsonPropertyName("resultsPerPage")] public int ResultsPerPage { get; set; }
    
    /// <summary>
    /// May be used in subsequent requests to identify the starting point for the next request
    /// </summary>
    [JsonPropertyName("startIndex")] public int StartIndex { get; set; }
    
    /// <summary>
    /// Indicates the number of CVE that match the request criteria, including all parameters
    /// </summary>
    /// <seealso cref="ResultsPerPage"/>
    [JsonPropertyName("totalResults")] public int TotalResults { get; set; }
    
    /// <summary>
    /// Identify the format of the API Response.
    /// </summary>
    [JsonPropertyName("format")] public string Format { get; set; }
    
    /// <summary>
    /// Identify the version of the API Response.
    /// </summary>
    [JsonPropertyName("version")] public string Version { get; set; }
    
    /// <summary>
    /// Identifies when the response was generated
    /// </summary>
    [JsonPropertyName("timestamp")] public DateTime Timestamp { get; set; }
    
    /// <summary>
    /// Contains an array of objects equal to the number of CVE returned in the response.
    /// </summary>
    [JsonPropertyName("vulnerabilities")] public Vulnerability[] Vulnerabilities { get; set; }

}