using System.Collections.Generic;
using NuGet.Versioning;
using NuGetDefense;

namespace NVDFeedImporter
{
    public static class vulnDictExtensionMethods
    {
        public static void MakeCorrections(this Dictionary<string, Dictionary<string, VulnerabilityEntry>> vulnDict)
        {
            vulnDict["bootstrap"]["CVE-2016-10735"].Versions = new []
            {
                new VersionRange(
                    new NuGetVersion(3,0, 0), true, new NuGetVersion(3,4,0), false).ToString(),
                "4.0.0-beta",
            };
            vulnDict["bootstrap"]["CVE-2018-14041"].Versions = new []
            {
                new VersionRange( maxVersion: new NuGetVersion(4, 1,2)).ToString()
            };
            
            vulnDict["bootstrap"]["CVE-2018-20677"].Versions = new []
            {
                new VersionRange( maxVersion: new NuGetVersion(3, 4,0)).ToString()
            };
            
            vulnDict["bootstrap"]["CVE-2018-20676"].Versions = new []
            {
                new VersionRange( maxVersion: new NuGetVersion(3, 4,0)).ToString()
            };
            
            vulnDict["bootstrap"]["CVE-2019-8331"].Versions = new []
            {
                new VersionRange( maxVersion: new NuGetVersion(3, 4,1)).ToString(),
                new VersionRange( new NuGetVersion(4,3,0),true,  new NuGetVersion(4, 3,1)).ToString()

            };
            
            vulnDict["bootstrap"]["CVE-2018-14042"].Versions = new []
            {
                new VersionRange( maxVersion: new NuGetVersion(4, 1,2)).ToString()
            };
        }
    }
}