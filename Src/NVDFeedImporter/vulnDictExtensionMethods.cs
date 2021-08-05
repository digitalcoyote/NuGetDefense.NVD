using System.Collections.Generic;
using NuGetDefense;

namespace NVDFeedImporter
{
    public static class VulnDictExtensionMethods
    {
        public static void MakeCorrections(this Dictionary<string, Dictionary<string, VulnerabilityEntry>> vulnDict)
        {
            if(vulnDict.ContainsKey("nlog"))
                vulnDict["nlog"].Remove("CVE-1999-1278");
            if(vulnDict.ContainsKey("twilio"))
                vulnDict["twilio"].Remove("CVE-2014-9023");
        }
    }
}