using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using NuGetDefense;
using NuGetDefense.NVD;
using Xunit;

namespace NVDFeedTests;

public class MessagePackTests : IAsyncLifetime
{
    private const string SystemNetHttpTestFeedFile = "./TestFiles/nvdcve-MessagePack.json";
    private NVDFeed _systemNetHttpTestFeed;
    private Dictionary<string, Dictionary<string, VulnerabilityEntry>> _vulnDict;

    public Task InitializeAsync()
    {
        return Task.Run(() =>
        {
            using var fs = File.OpenRead(SystemNetHttpTestFeedFile);
            _systemNetHttpTestFeed = JsonSerializer.DeserializeAsync<NVDFeed>(fs).Result;
            _vulnDict =
                new();
            FeedUpdater.AddFeedToVulnerabilityData(_systemNetHttpTestFeed, _vulnDict);
        });
    }

    public Task DisposeAsync()
    {
        return Task.CompletedTask;
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
}