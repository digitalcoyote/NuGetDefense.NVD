using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using MessagePack;
using NuGet.Versioning;
using NuGetDefense.Core;

namespace NuGetDefense.NVD
{
    public class Scanner
    {
        private readonly Dictionary<string, Dictionary<string, VulnerabilityEntry>> _nvdDict;

        public Scanner(string nugetFile, TimeSpan vulnDataReaTimeout, bool breakIfCannotRun = false, bool selfUpdate = false)
        {
            NugetFile = nugetFile;
            BreakIfCannotRun = breakIfCannotRun;
            var lz4Options = MessagePackSerializerOptions.Standard.WithCompression(MessagePackCompression.Lz4BlockArray)
                .WithSecurity(MessagePackSecurity.UntrustedData);
            var vulnDataFile = Path.Combine(Path.GetDirectoryName(AppContext.BaseDirectory)!,
                "VulnerabilityData.bin");
            if (!File.Exists(vulnDataFile))
            {
                _nvdDict = CreateNewVulnDataBin(vulnDataFile).Result;
            }
            else
            {
                var startDateTime = DateTime.Now.Add(vulnDataReaTimeout);
                bool ableToReadVulnerabilityData;
                do
                {
                    try
                    {
                        var nvdData = File.Open(vulnDataFile, FileMode.Open, FileAccess.Read);
                        ableToReadVulnerabilityData = false;
                        _nvdDict = MessagePackSerializer
                            .Deserialize<
                                Dictionary<string, Dictionary<string, VulnerabilityEntry>>>(nvdData, lz4Options);
                        nvdData.Close();
                    }
                    catch (Exception e)
                    {
                        ableToReadVulnerabilityData = DateTime.Now <= startDateTime;
                        if (!ableToReadVulnerabilityData && BreakIfCannotRun)
                            throw new TimeoutException($"Reading vulnerability data failed:'{vulnDataFile}'", e);
                    }
                } while (ableToReadVulnerabilityData);

                if (!selfUpdate) return;
                var recentFeed = FeedUpdater.GetRecentFeedAsync().Result;
                var modifiedFeed = FeedUpdater.GetModifiedFeedAsync().Result;
                FeedUpdater.AddFeedToVulnerabilityData(recentFeed, _nvdDict);
                FeedUpdater.AddFeedToVulnerabilityData(modifiedFeed, _nvdDict);
                VulnerabilityData.SaveToBinFile(_nvdDict, "VulnerabilityData.bin", vulnDataReaTimeout);
            }
        }

        public static async Task<Dictionary<string, Dictionary<string, VulnerabilityEntry>>> CreateNewVulnDataBin(string vulnDataFile)
        {
            var vulnDict = new Dictionary<string, Dictionary<string, VulnerabilityEntry>>();
            await foreach (var feed in FeedUpdater.GetFeedsAsync())
                FeedUpdater.AddFeedToVulnerabilityData(feed, vulnDict);
            VulnerabilityData.SaveToBinFile(vulnDict, vulnDataFile, TimeSpan.FromMinutes(10));
            return vulnDict;
        }

        private string NugetFile { get; }
        private bool BreakIfCannotRun { get; }

        public Dictionary<string, Dictionary<string, Vulnerability>> GetVulnerabilitiesForPackages(NuGetPackage[] pkgs,
            Dictionary<string, Dictionary<string, Vulnerability>> vulnDict = null)
        {
            try
            {
                vulnDict ??= new();
                foreach (var pkg in pkgs)
                {
                    var pkgId = pkg.Id.ToLower();
                    var pkgUrl = pkg.PackageUrl.ToLower();
                    if (!_nvdDict.ContainsKey(pkgId)) continue;
                    foreach (var cve in _nvdDict[pkgId].Keys.Where(cve => _nvdDict[pkgId][cve].Versions.Any(v =>
                        VersionRange.Parse(v.Replace('_','-')).Satisfies(new(pkg.Version)))))
                    {
                        if (!vulnDict.ContainsKey(pkgUrl)) vulnDict.Add(pkgUrl, new());
                        if (!vulnDict[pkgUrl].ContainsKey(cve))
                            vulnDict[pkgUrl].Add(cve, ToVulnerability(cve, _nvdDict[pkgId][cve]));
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(
                    $"{NugetFile} : {(BreakIfCannotRun ? "Error" : "Warning")} : NuGetDefense : NVD scan failed with exception: {e}");
            }

            return vulnDict;
        }

        public Vulnerability ToVulnerability(string cve,
            VulnerabilityEntry vulnerability)
        {
            return new(
                cve,
                vulnerability.Score ?? -1,
                vulnerability.Cwe,
                vulnerability.Description,
                null,
                vulnerability.Vector,
                vulnerability.Vendor
            );
        }
    }
}