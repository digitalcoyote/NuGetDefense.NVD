using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using MessagePack;
using NuGet.Versioning;
using NuGetDefense.Core;
using NugetDefense.NVD.API;

namespace NuGetDefense.NVD;

public class Scanner
{
    private readonly Dictionary<string, Dictionary<string, VulnerabilityEntry>> _nvdDict;
    private readonly Client? _nvdApiClient;

    public Scanner(string nugetFile,  string vulnDataFile, TimeSpan vulnDataReaTimeout, Client nvdApiClient, Dictionary<string, Dictionary<string, VulnerabilityEntry>> nvdDict, bool breakIfCannotRun = false, bool selfUpdate = false)
    {
        _nvdApiClient = nvdApiClient;
        _nvdDict = nvdDict;
        NugetFile = nugetFile;
        BreakIfCannotRun = breakIfCannotRun;
        var lz4Options = MessagePackSerializerOptions.Standard.WithCompression(MessagePackCompression.Lz4BlockArray)
            .WithSecurity(MessagePackSecurity.UntrustedData);

        if (!File.Exists(vulnDataFile))
        {
            _nvdDict = VulnerabilityDataUpdater.CreateNewVulnDataBin(vulnDataFile, nvdApiClient).Result;
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
            var startDate = File.GetLastAccessTimeUtc(vulnDataFile).Add(TimeSpan.FromDays(-1));
            var nvdApiOptions = new CvesRequestOptions
            {
                StartIndex = 0,
                LastModStartDate = startDate
            };
            Debug.Assert(_nvdDict != null, nameof(_nvdDict) + " != null");
            _nvdDict = VulnerabilityDataUpdater.UpdateVulnerabilityDataFromApi(nvdApiClient, nvdApiOptions, _nvdDict).Result;
            VulnerabilityData.SaveToBinFile(_nvdDict, "VulnerabilityData.bin", vulnDataReaTimeout);
        }
    }

    private string NugetFile { get; }
    private bool BreakIfCannotRun { get; }

    public async Task<Dictionary<string, Dictionary<string, Vulnerability>>> GetVulnerabilitiesForPackagesUsingApiAsync(NuGetPackage[] pkgs,
        Dictionary<string, Dictionary<string, Vulnerability>>? vulnDict = null)
    {
        try
        {
            vulnDict ??= new();
            foreach (var pkg in pkgs)
            {
                var options = new CvesRequestOptions
                {
                    StartIndex = 0,
                    VirtualMatchString = $"cpe:2.3:*:*:{pkg.Id}:*:*:*:*",
                };
                await GetVulnerabilitiesForPackage(_nvdApiClient, options, vulnDict);
            }
        }
        catch (Exception e)
        {
            Console.WriteLine(
                $"{NugetFile} : {(BreakIfCannotRun ? "Error" : "Warning")} : NuGetDefense : NVD API scan failed with exception: {e}");
        }

        return vulnDict;
    }

    private static async Task GetVulnerabilitiesForPackage(Client nvdApiClient, CvesRequestOptions options, Dictionary<string, Dictionary<string, Vulnerability>> vulnDict)
    {
        var startIndex = options.StartIndex;
        var totalResults = 0;
        const int retriesMax = 10;
        var retries = 0;
        
        do
        {
            CveResponse? response = null;

            options.StartIndex = startIndex;

            try
            {
                response = await nvdApiClient.GetCvesAsync(options);
            }
            catch(Exception e)
            {
                // Consider a better way to log this out (pass in a logger?)
                Console.WriteLine($"Exception encountered while retrieving CVEs from the NVD API: {e}");
            }

            if (response?.StatusCode == HttpStatusCode.TooManyRequests)
            {
                Thread.Sleep(TimeSpan.FromSeconds(3));
            }
            else if(response is { IsSuccessStatusCode: true })
            {
                // AddFeedToVulnerabilityData(response, vulnDict);
                totalResults = response.TotalResults;
                startIndex += response.ResultsPerPage;
                retries = 0;
            }
            else
            {
                retries++;
            }
            
        } while (startIndex < totalResults && retries <= retriesMax);
    }

    public Dictionary<string, Dictionary<string, Vulnerability>> GetVulnerabilitiesForPackages(NuGetPackage[] pkgs,
        Dictionary<string, Dictionary<string, Vulnerability>>? vulnDict = null)
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
                             VersionRange.Parse(v.Replace('_', '-')).Satisfies(new(pkg.Version)))))
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