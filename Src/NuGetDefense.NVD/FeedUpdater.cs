using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using NuGet.Versioning;
using NuGetDefense.Core;
using NVDFeedImporter;

namespace NuGetDefense.NVD
{
    public class FeedUpdater
    {
        public static void AddFeedToVulnerabilityData(NVDFeed feed,
            Dictionary<string, Dictionary<string, VulnerabilityEntry>> nvdDict)
        {
            foreach (var feedVuln in feed.CveItems)
            {
                var versions = new List<string>();
                var validNuGetPackage = true;
                foreach (var match in feedVuln.Configurations.Nodes.Where(n => n.CpeMatch != null)
                    .SelectMany(n => n.CpeMatch))
                {
                    var cpe = Cpe.Parse(match.Cpe23Uri);
                    if (cpe.Part != "a") continue;
                    if (cpe.ProductVersion == "-" || cpe.ProductVersion == "*")
                    {
                        NuGetVersion start = null;
                        NuGetVersion end = null;
                        var includeStart = false;
                        var includeEnd = false;
                        if (!string.IsNullOrWhiteSpace(match.VersionStartIncluding))
                        {
                            validNuGetPackage = validNuGetPackage &&
                                                NuGetVersion.TryParse(match.VersionStartIncluding, out start);
                            includeStart = true;
                        }

                        if (!string.IsNullOrWhiteSpace(match.VersionEndIncluding))
                        {
                            validNuGetPackage = validNuGetPackage &&
                                                NuGetVersion.TryParse(match.VersionEndExcluding, out end);
                            includeEnd = true;
                        }
                        else if (!string.IsNullOrWhiteSpace(match.VersionEndExcluding))
                        {
                            validNuGetPackage = validNuGetPackage &&
                                                NuGetVersion.TryParse(match.VersionEndExcluding, out end);
                        }

                        if (!validNuGetPackage) continue;
                        var range = new VersionRange(start, includeStart, end, includeEnd);

                        versions.Add(string.IsNullOrWhiteSpace(range.ToString()) ? "*" : range.ToString());
                        if (versions.Count > 1) versions = versions.Where(s => s != "*").ToList();
                    }

                    var cwe = "";
                    if (feedVuln.Cve.Problemtype.ProblemtypeData.Any())
                        if (feedVuln.Cve.Problemtype.ProblemtypeData[0].Description.Any())
                            cwe = feedVuln.Cve.Problemtype.ProblemtypeData[0].Description[0].Value;

                    var description = "";
                    if (feedVuln.Cve.Description.DescriptionData.Any()) description = feedVuln.Cve.Description.DescriptionData.First().Value;

                    if (!nvdDict.ContainsKey(cpe.Product))
                        nvdDict.Add(cpe.Product,
                            new Dictionary<string, VulnerabilityEntry>());
                    if (!nvdDict[cpe.Product].ContainsKey(feedVuln.Cve.CveDataMeta.Id))
                    {
                        var specifiedVector = Enum.TryParse<Vulnerability.AccessVectorType>(
                            feedVuln.Impact.BaseMetricV3?.CvssV3?.AttackVector, out var vector);
                        nvdDict[cpe.Product].Add(feedVuln.Cve.CveDataMeta.Id, new VulnerabilityEntry
                            {
                                Versions = versions.ToArray(),
                                Description = description,
                                Cwe = cwe,
                                Vendor = cpe.Vendor,
                                Score = feedVuln.Impact.BaseMetricV3?.CvssV3?.BaseScore,
                                Vector = specifiedVector ? vector : Vulnerability.AccessVectorType.UNSPECIFIED,
                                References = feedVuln.Cve.References.ReferenceData.Select(r => r.Url.ToString())
                                    .ToArray()
                            }
                        );
                    }
                    else
                    {
                        var vuln = nvdDict[cpe.Product][feedVuln.Cve.CveDataMeta.Id];
                        var versionList = vuln.Versions.Union(versions);
                        vuln.Versions = versionList.ToArray();
                    }
                }
            }
        }

        public static IEnumerable<string> GetJsonLinks(string linkRegex = "")
        {
            using var client = new WebClient();
            if (string.IsNullOrWhiteSpace(linkRegex))
                linkRegex =
                    @"(https:\/\/nvd\.nist\.gov)*\/feeds\/json\/cve\/\d{0,4}\.?\d{0,4}\.?\/nvdcve-\d{0,4}\.?\d{0,4}\.?-\d{4}\.json\.zip";

            var feedsPage = client.DownloadString("https://nvd.nist.gov/vuln/data-feeds");
            var ls = Regex.Matches(feedsPage,
                linkRegex,
                RegexOptions.Singleline).Cast<Match>().Select(m => m.ToString()).ToImmutableArray();
            return ls;
        }

        public static async IAsyncEnumerable<NVDFeed> GetFeedsAsync()
        {
            foreach (var link in GetJsonLinks()) yield return await GetFeedAsync(link);
        }

        public static NVDFeed GetFeed(string link)
        {
            return GetFeedAsync(link).Result;
        }

        public static async Task<NVDFeed> GetRecentFeedAsync()
        {
            var link = GetJsonLinks(@"(https:\/\/nvd\.nist\.gov)*\/feeds\/json\/cve\/\d{0,4}\.?\d{0,4}\.?\/nvdcve-\d{0,4}\.?\d{0,4}\.?-recent\.json\.zip").FirstOrDefault();
            return await GetFeedAsync(link);
        }

        public static async Task<NVDFeed> GetModifiedFeedAsync()
        {
            var link = GetJsonLinks(@"(https:\/\/nvd\.nist\.gov)*\/feeds\/json\/cve\/\d{0,4}\.?\d{0,4}\.?\/nvdcve-\d{0,4}\.?\d{0,4}\.?-modified\.json\.zip").FirstOrDefault();
            return await GetFeedAsync(link);
        }

        private static async Task<NVDFeed> GetFeedAsync(string link)
        {
            using var feedDownloader = new WebClient();
            Stream jsonZippedDataStream = new MemoryStream(feedDownloader.DownloadData(@$"https://nvd.nist.gov{link.Substring(link.IndexOf("https://nvd.nist.gov") + 1)}"));
            var zipFile = new ZipArchive(jsonZippedDataStream);
            var entryStream = zipFile.Entries[0].Open();
            return await JsonSerializer.DeserializeAsync<NVDFeed>(entryStream, new JsonSerializerOptions());
        }
    }
}