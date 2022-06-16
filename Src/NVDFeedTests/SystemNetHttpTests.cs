using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using NuGetDefense;
using NuGetDefense.NVD;
using Xunit;

namespace NVDFeedTests
{
    public class SystemNetHttpTests : IAsyncLifetime
    {
        private const string SystemNetHttpTestFeedFile = "./TestFiles/nvdcve-System.Net.Http.json";
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
        public void CorrectSystemNetHttpVulnerabilityVersions()
        {
            var versions = _vulnDict["system.net.http"]["CVE-2017-0249"].Versions;
            var expectedVersions = new[]
            {
                "[4.1.1]",
                "[4.3.1]"
            };
            Assert.False(versions.Except(expectedVersions).Any());
        }
    }
}