using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace NuGetDefense.NVD;

/// <summary>
/// Old class for parsing NVD JSON feeds
/// </summary>
/// <see cref="VulnerabilityDataUpdater"/>
[Obsolete("Use VulnerabilityDataUpdater instead")]
public class FeedUpdater : VulnerabilityDataUpdater
{
    [Obsolete]
    public static ImmutableArray<string> GetJsonLinks(string linkRegex = "")
    {
        using var client = new WebClient();
        if (string.IsNullOrWhiteSpace(linkRegex))
            linkRegex =
                @"(https:\/\/nvd\.nist\.gov)*\/feeds\/json\/cve\/\d{0,4}\.?\d{0,4}\.?\/nvdcve-\d{0,4}\.?\d{0,4}\.?-\d{4}\.json\.zip";

        var feedsPage = client.DownloadString("https://nvd.nist.gov/vuln/data-feeds");
        var ls = Regex.Matches(feedsPage,
            linkRegex,
            RegexOptions.Singleline).Select(m => m.ToString()).ToImmutableArray();
        return ls;
    }

    [Obsolete]
    public static async IAsyncEnumerable<NVDFeed> GetFeedsAsync()
    {
        var links = GetJsonLinks();
        if (links.Length < DateTime.Now.Year - 2001) throw new("Unable to read feeds from NVD");
        for (var index = 0; index < links.Length; index++)
        {
            var link = links[index];
            yield return await GetFeedAsync(link);
        }
    }

    [Obsolete]
    public static NVDFeed GetFeed(string link)
    {
        return GetFeedAsync(link).Result;
    }

    [Obsolete]
    public static async Task<NVDFeed> GetRecentFeedAsync()
    {
        var link = GetJsonLinks(@"(https:\/\/nvd\.nist\.gov)*\/feeds\/json\/cve\/\d{0,4}\.?\d{0,4}\.?\/nvdcve-\d{0,4}\.?\d{0,4}\.?-recent\.json\.zip").FirstOrDefault();
        return await GetFeedAsync(link);
    }

    [Obsolete]
    public static async Task<NVDFeed> GetModifiedFeedAsync()
    {
        var link = GetJsonLinks(@"(https:\/\/nvd\.nist\.gov)*\/feeds\/json\/cve\/\d{0,4}\.?\d{0,4}\.?\/nvdcve-\d{0,4}\.?\d{0,4}\.?-modified\.json\.zip").FirstOrDefault();
        return await GetFeedAsync(link);
    }

    [Obsolete]
    private static async Task<NVDFeed> GetFeedAsync(string link)
    {
        using var feedDownloader = new WebClient();
        Stream jsonZippedDataStream =
            new MemoryStream(feedDownloader.DownloadData(@$"https://nvd.nist.gov{link[(link.IndexOf("https://nvd.nist.gov", StringComparison.Ordinal) + 1)..]}"));
        var zipFile = new ZipArchive(jsonZippedDataStream);
        var entryStream = zipFile.Entries[0].Open();
        return await JsonSerializer.DeserializeAsync<NVDFeed>(entryStream, new JsonSerializerOptions());
    }

    [Obsolete]
    public static async Task<NVDFeed> GetFeedFromFile(string file)
    {
        Stream entryStream = File.OpenRead(file);
        return await JsonSerializer.DeserializeAsync<NVDFeed>(entryStream, new JsonSerializerOptions());
    }
}