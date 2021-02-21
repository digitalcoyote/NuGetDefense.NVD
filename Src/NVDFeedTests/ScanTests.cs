using System;
using NuGetDefense;
using NuGetDefense.NVD;
using Xunit;

namespace NVDFeedTests
{
    public class ScanTests
    {
        [Fact]
        public void Log4NetTest()
        {
            var scanner = new Scanner("/test.proj", TimeSpan.FromMinutes(5), true, true);
            var vulns = scanner.GetVulnerabilitiesForPackages(new[] {new NuGetPackage() {Id = "log4net", Version = "2.0.5"}});
            Assert.True(vulns.ContainsKey("pkg:nuget/log4net@2.0.8"));
        }
    }
}