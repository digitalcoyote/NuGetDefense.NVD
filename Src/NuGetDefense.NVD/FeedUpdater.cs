using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Text;
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
                var versionsDict = new Dictionary<string, List<string>>();
                var validNuGetPackage = true;
                foreach (var match in feedVuln.Configurations.Nodes.Where(n => n.CpeMatch != null)
                    .SelectMany(n => n.CpeMatch))
                {
                    var cpe = Cpe.Parse(match.Cpe23Uri);
                    if (cpe.Part != "a") continue;
                    if(!versionsDict.ContainsKey(cpe.Product)) versionsDict.Add(cpe.Product, new List<string>());
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
                                                NuGetVersion.TryParse(match.VersionEndIncluding, out end);
                            includeEnd = true;
                        }
                        else if (!string.IsNullOrWhiteSpace(match.VersionEndExcluding))
                        {
                            validNuGetPackage = validNuGetPackage &&
                                                NuGetVersion.TryParse(match.VersionEndExcluding, out end);
                        }

                        if (!validNuGetPackage) continue;
                        var range = new VersionRange(start, includeStart, end, includeEnd);

                        versionsDict[cpe.Product].Add(string.IsNullOrWhiteSpace(range.ToString()) ? "*" : range.ToString());
                        if (versionsDict[cpe.Product].Count > 1) versionsDict[cpe.Product] = versionsDict[cpe.Product].Where(s => s != "*").ToList();
                    }
                    else
                    {
                        versionsDict[cpe.Product].Add(String.IsNullOrWhiteSpace(cpe.Update) || cpe.Update == "*" ? $"[{cpe.ProductVersion}]" : $"[{cpe.ProductVersion}-{cpe.Update}]");
                    }

                    var cwe = "";
                    if (feedVuln.Cve.Problemtype.ProblemtypeData.Any())
                        if (feedVuln.Cve.Problemtype.ProblemtypeData[0].Description.Any())
                            cwe = feedVuln.Cve.Problemtype.ProblemtypeData[0].Description[0].Value;

                    var description = "";
                    if (feedVuln.Cve.Description.DescriptionData.Any())
                    {
                        var sb = new StringBuilder(feedVuln.Cve.Description.DescriptionData[0].Value);
                        for (var index = 1; index < feedVuln.Cve.Description.DescriptionData.Length; index++)
                        {
                            sb.AppendLine(feedVuln.Cve.Description.DescriptionData[index].Value);
                        }

                        description = sb.ToString();

                    }

                    if (!nvdDict.ContainsKey(cpe.Product))
                        nvdDict.Add(cpe.Product,
                            new Dictionary<string, VulnerabilityEntry>());
                    if (!nvdDict[cpe.Product].ContainsKey(feedVuln.Cve.CveDataMeta.Id))
                    {
                        var specifiedVector = Enum.TryParse<Vulnerability.AccessVectorType>(
                            feedVuln.Impact.BaseMetricV3?.CvssV3?.AttackVector, out var vector);
                        nvdDict[cpe.Product].Add(feedVuln.Cve.CveDataMeta.Id, new VulnerabilityEntry
                            {
                                Versions = versionsDict[cpe.Product].ToArray(),
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
                        vuln.Versions = vuln.Versions.Union(versionsDict[cpe.Product]).ToArray();
                        nvdDict[cpe.Product][feedVuln.Cve.CveDataMeta.Id] = vuln;
                    }
                }
            }
        }

        public static ImmutableArray<string> GetJsonLinks(string linkRegex = "")
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
            var links = GetJsonLinks();
            if (links.Length < DateTime.Now.Year - 2001) throw new Exception("Unable to read feeds from NVD");
            for (var index = 0; index < links.Length; index++)
            {
                var link = links[index];
                yield return await GetFeedAsync(link);
            }
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
            Stream jsonZippedDataStream = new MemoryStream(feedDownloader.DownloadData(@$"https://nvd.nist.gov{link[(link.IndexOf("https://nvd.nist.gov", StringComparison.Ordinal) + 1)..]}"));
            var zipFile = new ZipArchive(jsonZippedDataStream);
            var entryStream = zipFile.Entries[0].Open();
            return await JsonSerializer.DeserializeAsync<NVDFeed>(entryStream, new JsonSerializerOptions());
        }

        public static async Task<NVDFeed> GetFeedFromFile(string file)
        {
            Stream entryStream = File.OpenRead(file);
            return await JsonSerializer.DeserializeAsync<NVDFeed>(entryStream, new JsonSerializerOptions());
        }
    }
}