using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Configuration;
using NuGetDefense;
using NuGetDefense.Core;
using NuGetDefense.NVD;
using NugetDefense.NVD.API;
using Xunit;

namespace NVDFeedTests;

public class BootStrapTests : IDisposable
{
    private const string BoostrapTestFeedFile = "./TestFiles/nvdcve-bootstrap.json";
    private readonly Client _client;
    private readonly Dictionary<string, Dictionary<string, VulnerabilityEntry>> _vulnDict = new();

    public BootStrapTests()
    {
        var configuration = new ConfigurationBuilder()
            .AddUserSecrets<BootStrapTests>()
            .Build();

        var startIndex = 0;
        var totalResults = 0;
        _client = new(configuration["ApiKey"]);

        do
        {
            var options = new CvesRequestOptions
            {
                StartIndex = startIndex,
                VirtualMatchString = "cpe:2.3:*:*:bootstrap:*:*:*:*"
            };

            var response = _client.GetCvesAsync(options).Result;
            
            FeedUpdater.AddFeedToVulnerabilityData(response, _vulnDict);
            
            totalResults = response.TotalResults;
        } while (startIndex < totalResults);
    }

    public void Dispose()
    {
        _client?.Dispose();
    }

    [Fact]
    public void CorrectVulnerabilityVersions()
    {
        var versions = _vulnDict.FindCve("CVE-2018-14040")?.Versions;
        var expectedVersions = new[]
        {
            "[4.0.0, 4.1.2)",
            "(, 3.4.0)",
            "[4.0.0-alpha]",
            "[4.0.0-alpha2]",
            "[4.0.0-alpha3]",
            "[4.0.0-alpha4]",
            "[4.0.0-alpha5]",
            "[4.0.0-alpha6]",
            "[4.0.0-beta]",
            "[4.0.0-beta2]",
            "[4.0.0-beta3]"
        };
        Assert.False(versions.Except(expectedVersions).Any());
    }
}