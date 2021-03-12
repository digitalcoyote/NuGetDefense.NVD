using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using NuGetDefense;
using NuGetDefense.NVD;
using NVDFeedImporter;
using Xunit;

namespace NVDFeedTests
{
    public class NLogTests : IAsyncLifetime
    {
        private const string SystemNetHttpTestFeedFile = "./TestFiles/nvdcve-NLog.json";
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
                _vulnDict.MakeCorrections();
            });
        }

        public Task DisposeAsync()
        {
            return Task.CompletedTask;
        }
        
        [Fact]
        public void CorrectNLogVulnerabilityVersions()
        {
            Assert.Empty(_vulnDict["nlog"]);
        }
    }
}