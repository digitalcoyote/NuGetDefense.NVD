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
    public class JQueryCpeParsingTests : IAsyncLifetime
    {
        private const string SystemNetHttpTestFeedFile = "./TestFiles/nvdcve-JQuery.json";
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
        public void CorrectJQueryVulnerabilityVersions()
        {
            var versions = _vulnDict["jquery"]["CVE-2016-10707"].Versions;
            var expectedVersions = new[]
            {
               "[3.0.0-rc1]"
            };
            Assert.False(versions.Except(expectedVersions).Any());
        }
    }
}