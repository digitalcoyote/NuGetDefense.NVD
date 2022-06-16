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
            var vulnDict =
                new Dictionary<string, Dictionary<string, VulnerabilityEntry>>();
            await foreach (var feed in FeedUpdater.GetFeedsAsync())
                FeedUpdater.AddFeedToVulnerabilityData(feed, vulnDict);
            vulnDict.MakeCorrections();

            for (var index = 0; index < args.Length; index++)
            {
                if(Directory.Exists(args[index]))
                    VulnerabilityData.SaveToBinFile(vulnDict, Path.Combine(args[index], BinName), TimeSpan.FromMinutes(10));
            }
        }
    }
}