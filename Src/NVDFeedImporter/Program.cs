using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using NuGetDefense;
using NuGetDefense.NVD;
using NugetDefense.NVD.API;

namespace NVDFeedImporter;

internal class Program
{
    private const string BinName = "VulnerabilityData.bin";
    
    private static async Task Main(string[] args)
    {
        var client = new Client(); // Needs support to pass in API Key
        
        var options = new CvesRequestOptions
        {
            StartIndex = 0,
        };
        
        var vulnDict = await VulnerabilityDataUpdater.UpdateVulnerabilityDataFromApi(client, options, new()); 

        vulnDict.MakeCorrections();

        foreach (var t in args)
            if (Directory.Exists(t))
                VulnerabilityData.SaveToBinFile(vulnDict, Path.Combine(t, BinName), TimeSpan.FromMinutes(10));
    }
}