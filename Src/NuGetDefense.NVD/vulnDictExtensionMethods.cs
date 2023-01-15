using System.Collections.Generic;
using System.Linq;
using NuGetDefense;

namespace NuGetDefense.NVD
{
    public static class VulnDictExtensionMethods
    {
        /// <summary>
        /// Applies corrections to the NVD Feed to correct mismatched package names or versions
        /// </summary>
        /// <param name="vulnDict"></param>
        public static void MakeCorrections(this Dictionary<string, Dictionary<string, VulnerabilityEntry>> vulnDict)
        {
            if(vulnDict.ContainsKey("nlog"))
                vulnDict["nlog"].Remove("CVE-1999-1278");
            if(vulnDict.ContainsKey("twilio"))
                vulnDict["twilio"].Remove("CVE-2014-9023");
            
            if (vulnDict.ContainsKey("chakracore"))
            {
                if (!vulnDict.ContainsKey("microsoft.chakracore"))
                {
                    // ChakraCore's nuget package is Microsoft.ChakraCore
                    vulnDict.Add("microsoft.chakracore", vulnDict["chakracore"]);
                }
                else
                {
                    // If updating, we add the new chakracore vulns to microsoft.chakracore
                    foreach (var key in vulnDict["chakracore"].Keys)
                    {
                        if (vulnDict["microsoft.chakracore"].ContainsKey(key))
                        {
                            vulnDict["microsoft.chakracore"][key] = vulnDict["chakracore"][key];
                        }
                        else
                        {
                            vulnDict["microsoft.chakracore"].Add(key, vulnDict["chakracore"][key]);
                        }

                    }
                }

                vulnDict.Remove("chakracore");
            }
        }
    }
}