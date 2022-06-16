using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using NuGetDefense;
using NuGetDefense.Core;
using NuGetDefense.NVD;
using Xunit;

namespace NVDFeedTests
{
    public class BootStrapTests : IAsyncLifetime
    {
        private const string BoostrapTestFeedFile = "./TestFiles/nvdcve-bootstrap.json";
        private NVDFeed _boostrapTestFeed;
        private Dictionary<string, Dictionary<string, VulnerabilityEntry>> _vulnDict;

        public Task InitializeAsync()
        {
            return Task.Run(() =>
            {
                using var fs = File.OpenRead(BoostrapTestFeedFile);
                _boostrapTestFeed = JsonSerializer.DeserializeAsync<NVDFeed>(fs).Result;
                _vulnDict =
                    new();
                FeedUpdater.AddFeedToVulnerabilityData(_boostrapTestFeed, _vulnDict);
            });
        }

        public Task DisposeAsync()
        {
            return Task.CompletedTask;
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
}