using System;
using System.Linq;
using NuGetDefense.NVD;
using Xunit;

namespace NVDFeedTests
{
    public class FeedUpdaterTests
    {
        /// <summary>
        /// Tests that all the feeds are being found. It starts in 2002, so removing 2001 from the current year should get the correct number of feeds
        /// </summary>
        [Fact]
        public void GetJsonLinks()
        {
            var links = FeedUpdater.GetJsonLinks();
            Assert.Equal(DateTime.Now.Year - 2001, links.Count());
        }
    }
}