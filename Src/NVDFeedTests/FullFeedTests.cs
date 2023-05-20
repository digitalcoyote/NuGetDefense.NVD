using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using Microsoft.Extensions.Configuration;
using NuGetDefense;
using NuGetDefense.Core;
using NuGetDefense.NVD;
using NugetDefense.NVD.API;
using Xunit;

namespace NVDFeedTests;

public class FullFeedTests : IDisposable
{
    private readonly Client _client;
    private readonly Dictionary<string, Dictionary<string, VulnerabilityEntry>> _vulnDict = new();

    public FullFeedTests()
    {
        var configuration = new ConfigurationBuilder()
            .AddUserSecrets<FullFeedTests>()
            .Build();


        _client = new(configuration["ApiKey"]);
        
        var options = new CvesRequestOptions
        {
            StartIndex = 0,
            // VirtualMatchString = "cpe:2.3:*:*:bootstrap:*:*:*:*",
        };
        _vulnDict = VulnerabilityDataUpdater.UpdateVulnerabilityDataFromApi(_client, options, new()).Result;        
    }

    public void Dispose()
    {
        _client?.Dispose();
    }

    [Fact]
    public void CorrectBootstrapVulnerabilityVersions()
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
    
    [Fact]
    public void CorrectJQueryVulnerabilityVersions()
    {
        var versions = _vulnDict["jquery"]["CVE-2016-10707"].Versions;
        var expectedVersions = new[]
        {
            "[3.0.0-rc1]"
        };
        Assert.False(versions.Except(expectedVersions).Any());
    }
    
    [Fact]
    public void CorrectLog4NetVulnerabilityVersions()
    {
        var versions = _vulnDict["log4net"]["CVE-2018-1285"].Versions;
        var expectedVersions = new[]
        {
            "(, 2.0.8]"
        };
        Assert.False(versions.Except(expectedVersions).Any());
    }
    
    [Fact]
    public void CorrectMessagePackVulnerabilityVersions()
    {
        var versions = _vulnDict["messagepack"]["CVE-2020-5234"].Versions;
        var expectedVersions = new[]
        {
            "(, 1.9.3)",
            "[2.0.94-alpha]",
            "[2.0.110-alpha]",
            "[2.0.119-beta]",
            "[2.0.123-beta]",
            "[2.0.204-beta]",
            "[2.0.270-rc]",
            "[2.0.299-rc]",
            "[2.0.323, 2.1.80)"
        };
        Assert.False(versions.Except(expectedVersions).Any());
    }
    
    [Fact]
    public void CorrectNLogVulnerabilityVersions()
    {
        Assert.Empty(_vulnDict["nlog"]);
    }
}