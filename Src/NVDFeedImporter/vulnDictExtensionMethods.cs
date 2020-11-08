using System.Collections.Generic;
using NuGet.Versioning;
using NuGetDefense;

namespace NVDFeedImporter
{
    public static class vulnDictExtensionMethods
    {
        public static void MakeCorrections(this Dictionary<string, Dictionary<string, VulnerabilityEntry>> vulnDict)
        {
            var vulnerabilityEntry = vulnDict["bootstrap"]["CVE-2016-10735"];
            vulnerabilityEntry.Versions = new[]
            {
                new VersionRange(
                    new NuGetVersion(3, 0, 0), true, new NuGetVersion(3, 4, 0)).ToString(),
                "4.0.0-beta"
            };
            vulnDict["bootstrap"]["CVE-2016-10735"] = vulnerabilityEntry;


            vulnerabilityEntry = vulnDict["bootstrap"]["CVE-2018-14041"];
            vulnerabilityEntry.Versions = new[]
            {
                new VersionRange(maxVersion: new NuGetVersion(4, 1, 2)).ToString()
            };
            vulnDict["bootstrap"]["CVE-2018-14041"] = vulnerabilityEntry;


            vulnerabilityEntry = vulnDict["bootstrap"]["CVE-2018-20677"];
            vulnerabilityEntry.Versions = new[]
            {
                new VersionRange(maxVersion: new NuGetVersion(3, 4, 0)).ToString()
            };
            vulnDict["bootstrap"]["CVE-2018-20677"] = vulnerabilityEntry;


            vulnerabilityEntry = vulnDict["bootstrap"]["CVE-2018-20676"];
            vulnerabilityEntry.Versions = new[]
            {
                new VersionRange(maxVersion: new NuGetVersion(3, 4, 0)).ToString()
            };
            vulnDict["bootstrap"]["CVE-2018-20676"] = vulnerabilityEntry;

            vulnerabilityEntry = vulnDict["bootstrap"]["CVE-2019-8331"];
            vulnerabilityEntry.Versions = new[]
            {
                new VersionRange(maxVersion: new NuGetVersion(3, 4, 1)).ToString(),
                new VersionRange(new NuGetVersion(4, 3, 0), true, new NuGetVersion(4, 3, 1)).ToString()
            };
            vulnDict["bootstrap"]["CVE-2019-8331"] = vulnerabilityEntry;


            vulnerabilityEntry = vulnDict["bootstrap"]["CVE-2018-14042"];
            vulnerabilityEntry.Versions = new[]
            {
                new VersionRange(maxVersion: new NuGetVersion(4, 1, 2)).ToString()
            };
            vulnDict["bootstrap"]["CVE-2018-14042"] = vulnerabilityEntry;

        }
    }
}