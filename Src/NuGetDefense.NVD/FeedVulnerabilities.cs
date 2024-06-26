// <auto-generated />
//
// To parse this JSON data, add NuGet 'Newtonsoft.Json' then do:
//
//    using NVDFeedImporter;
//
//    var feedVulnerabilities = FeedVulnerabilities.FromJson(jsonString);

using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NuGetDefense.NVD
{
    public partial class FeedVulnerabilities
    {
        [JsonPropertyName("cve")] public Cve Cve { get; set; }

        [JsonPropertyName("configurations")] public Configurations Configurations { get; set; }

        [JsonPropertyName("impact")] public Impact Impact { get; set; }

        [JsonPropertyName("publishedDate")] public string PublishedDate { get; set; }

        [JsonPropertyName("lastModifiedDate")] public string LastModifiedDate { get; set; }
    }

    public class Configurations
    {
        [JsonPropertyName("CVE_data_version")] public string CveDataVersion { get; set; }

        [JsonPropertyName("nodes")] public Node[] Nodes { get; set; }
    }

    public class Node
    {
        [JsonPropertyName("operator")] public string Operator { get; set; }

        [JsonPropertyName("cpe_match")] public CpeMatch[] CpeMatch { get; set; }

        [JsonPropertyName("children")] public Child[] Children { get; set; }
    }

    public class Child
    {
        [JsonPropertyName("operator")] public string Operator { get; set; }

        [JsonPropertyName("cpe_match")] public CpeMatch[] CpeMatch { get; set; }
    }

    public class CpeMatch
    {
        [JsonPropertyName("vulnerable")] public bool? Vulnerable { get; set; }

        [JsonPropertyName("cpe23Uri")] public string Cpe23Uri { get; set; }

        [JsonPropertyName("versionStartIncluding")]
        public string VersionStartIncluding { get; set; }

        [JsonPropertyName("versionEndIncluding")]
        public string VersionEndIncluding { get; set; }

        [JsonPropertyName("versionEndExcluding")]
        public string VersionEndExcluding { get; set; }
    }

    public class Cve
    {
        [JsonPropertyName("data_type")] public string DataType { get; set; }

        [JsonPropertyName("data_format")] public string DataFormat { get; set; }

        [JsonPropertyName("data_version")] public string DataVersion { get; set; }

        [JsonPropertyName("CVE_data_meta")] public CveDataMeta CveDataMeta { get; set; }

        [JsonPropertyName("problemtype")] public Problemtype Problemtype { get; set; }

        [JsonPropertyName("references")] public References References { get; set; }

        [JsonPropertyName("description")] public CveDescription Description { get; set; }
    }

    public class CveDataMeta
    {
        [JsonPropertyName("ID")] public string Id { get; set; }

        [JsonPropertyName("ASSIGNER")] public string Assigner { get; set; }
    }

    public class CveDescription
    {
        [JsonPropertyName("description_data")] public DescriptionDatumElement[] DescriptionData { get; set; }
    }

    public class DescriptionDatumElement
    {
        [JsonPropertyName("lang")] public string Lang { get; set; }

        [JsonPropertyName("value")] public string Value { get; set; }
    }

    public class Problemtype
    {
        [JsonPropertyName("problemtype_data")] public ProblemtypeDatum[] ProblemtypeData { get; set; }
    }

    public class ProblemtypeDatum
    {
        [JsonPropertyName("description")] public DescriptionDatumElement[] Description { get; set; }
    }

    public class References
    {
        [JsonPropertyName("reference_data")] public ReferenceDatum[] ReferenceData { get; set; }
    }

    public class ReferenceDatum
    {
        [JsonPropertyName("url")] public Uri Url { get; set; }

        [JsonPropertyName("name")] public string Name { get; set; }

        [JsonPropertyName("refsource")] public string Refsource { get; set; }

        [JsonPropertyName("tags")] public string[] Tags { get; set; }
    }

    public class Impact
    {
        [JsonPropertyName("baseMetricV3")] public BaseMetricV3 BaseMetricV3 { get; set; }

        [JsonPropertyName("baseMetricV2")] public BaseMetricV2 BaseMetricV2 { get; set; }
    }

    public class BaseMetricV2
    {
        [JsonPropertyName("cvssV2")] public CvssV2 CvssV2 { get; set; }

        [JsonPropertyName("severity")] public string Severity { get; set; }

        [JsonPropertyName("exploitabilityScore")]
        public double? ExploitabilityScore { get; set; }

        [JsonPropertyName("impactScore")] public double? ImpactScore { get; set; }

        [JsonPropertyName("acInsufInfo")] public bool? AcInsufInfo { get; set; }

        [JsonPropertyName("obtainAllPrivilege")]
        public bool? ObtainAllPrivilege { get; set; }

        [JsonPropertyName("obtainUserPrivilege")]
        public bool? ObtainUserPrivilege { get; set; }

        [JsonPropertyName("obtainOtherPrivilege")]
        public bool? ObtainOtherPrivilege { get; set; }

        [JsonPropertyName("userInteractionRequired")]
        public bool? UserInteractionRequired { get; set; }
    }

    public class CvssV2
    {
        [JsonPropertyName("version")] public string Version { get; set; }

        [JsonPropertyName("vectorString")] public string VectorString { get; set; }

        [JsonPropertyName("accessVector")] public string AccessVector { get; set; }

        [JsonPropertyName("accessComplexity")] public string AccessComplexity { get; set; }

        [JsonPropertyName("authentication")] public string Authentication { get; set; }

        [JsonPropertyName("confidentialityImpact")]
        public string ConfidentialityImpact { get; set; }

        [JsonPropertyName("integrityImpact")] public string IntegrityImpact { get; set; }

        [JsonPropertyName("availabilityImpact")]
        public string AvailabilityImpact { get; set; }

        [JsonPropertyName("baseScore")] public double? BaseScore { get; set; }
    }

    public class BaseMetricV3
    {
        [JsonPropertyName("cvssV3")] public CvssV3 CvssV3 { get; set; }

        [JsonPropertyName("exploitabilityScore")]
        public double? ExploitabilityScore { get; set; }

        [JsonPropertyName("impactScore")] public double? ImpactScore { get; set; }
    }

    public class CvssV3
    {
        [JsonPropertyName("version")] public string Version { get; set; }

        [JsonPropertyName("vectorString")] public string VectorString { get; set; }

        [JsonPropertyName("attackVector")] public string AttackVector { get; set; }

        [JsonPropertyName("attackComplexity")] public string AttackComplexity { get; set; }

        [JsonPropertyName("privilegesRequired")]
        public string PrivilegesRequired { get; set; }

        [JsonPropertyName("userInteraction")] public string UserInteraction { get; set; }

        [JsonPropertyName("scope")] public string Scope { get; set; }

        [JsonPropertyName("confidentialityImpact")]
        public string ConfidentialityImpact { get; set; }

        [JsonPropertyName("integrityImpact")] public string IntegrityImpact { get; set; }

        [JsonPropertyName("availabilityImpact")]
        public string AvailabilityImpact { get; set; }

        [JsonPropertyName("baseScore")] public decimal? BaseScore { get; set; }

        [JsonPropertyName("baseSeverity")] public string BaseSeverity { get; set; }
    }

    public partial class FeedVulnerabilities
    {
        public static FeedVulnerabilities[] FromJson(string json)
        {
            return JsonSerializer.Deserialize<FeedVulnerabilities[]>(json);
        }
    }
}