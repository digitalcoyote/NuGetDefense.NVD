using System.Collections.Generic;
using NuGetDefense;

namespace NVDFeedImporter
{
    public static class VulnDictExtensionMethods
    {
        public static void MakeCorrections(this Dictionary<string, Dictionary<string, VulnerabilityEntry>> vulnDict)
        {
            vulnDict["nlog"].Remove("CVE-1999-1278");
            vulnDict["twilio"].Remove("CVE-2014-9023");
        }
    }
}