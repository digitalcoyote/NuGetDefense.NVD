using System;
using NuGetDefense;
using NuGetDefense.NVD;
using Xunit;

namespace NVDFeedTests
{
    public class ScanTests
    {
        [Fact]
        public void log4NetTest()
        {
            var scanner = new Scanner("/test.proj", TimeSpan.FromMinutes(5), true, true);
            var vulns = scanner.GetVulnerabilitiesForPackages(new[] {new NuGetPackage() {Id = "log4Net", Version = "2.0.8"}});
            // Assert.Contains()
        }
    }
}