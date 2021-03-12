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
    public class Log4NetCpeParsingTests : IAsyncLifetime
    {
        private const string SystemNetHttpTestFeedFile = "./TestFiles/nvdcve-Log4Net.json";
        private NVDFeed _systemNetHttpTestFeed;
        private Dictionary<string, Dictionary<string, VulnerabilityEntry>> _vulnDict;

        public Task InitializeAsync()
        {
            return Task.Run(() =>
            {
                using var fs = File.OpenRead(SystemNetHttpTestFeedFile);
                _systemNetHttpTestFeed = JsonSerializer.DeserializeAsync<NVDFeed>(fs).Result;
                _vulnDict =
                    new Dictionary<string, Dictionary<string, VulnerabilityEntry>>();
                FeedUpdater.AddFeedToVulnerabilityData(_systemNetHttpTestFeed, _vulnDict);
            });
        }

        public Task DisposeAsync()
        {
            return Task.CompletedTask;
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
    }
}