using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using NuGetDefense;
using NuGetDefense.NVD;

namespace NVDFeedImporter
{
    internal class Program
    {
        private const string BinName = "VulnerabilityData.bin";

        private static async Task Main(string[] args)
        {
            var outPath = BinName;
            if (args.Length > 0) outPath = Path.Combine(args[0], BinName);
            var vulnDict =
                new Dictionary<string, Dictionary<string, VulnerabilityEntry>>();
            await foreach (var feed in FeedUpdater.GetFeedsAsync())
                FeedUpdater.AddFeedToVulnerabilityData(feed, vulnDict);
            vulnDict.MakeCorrections();
            VulnerabilityData.SaveToBinFile(vulnDict, outPath, TimeSpan.FromMinutes(10));
        }
    }
}