using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Threading.RateLimiting;
using System.Web;

namespace NugetDefense.NVD.API;

public class Client : IDisposable
{
    private const string BaseUri = "https://services.nvd.nist.gov/rest/json/";
    private const string Version = "0.0.1";
    private readonly string? _apiKey;
    private readonly HttpClient _client;
    private readonly SlidingWindowRateLimiter _rateLimiter;

    public Client(string? apiKey = null, string userAgent = $@"NuGetDefense.NVD.API.Client/{Version} (https://github.com/digitalcoyote/NuGetDefense.NVD/blob/master/README.md)")
    {
        SlidingWindowRateLimiterOptions rateLimiterOptions =  new ()
        {
            AutoReplenishment = true,
            PermitLimit = 5,
            QueueLimit = 5000,
            SegmentsPerWindow = 10,
            Window = TimeSpan.FromSeconds(30),
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
        };
        
        if (!string.IsNullOrWhiteSpace(apiKey))
        {
            rateLimiterOptions.PermitLimit = 50;
        }


        _rateLimiter = new (rateLimiterOptions);
        _client = new(new ClientSideRateLimitedHandler(_rateLimiter));

        if (!string.IsNullOrWhiteSpace(userAgent)) _client.DefaultRequestHeaders.UserAgent.ParseAdd(userAgent);
        if (!string.IsNullOrWhiteSpace(apiKey)) _client.DefaultRequestHeaders.Add("apikey", apiKey);

    }

    public void Dispose()
    {
        _client.Dispose();
    }

    /// <summary>
    ///     Calls the API with the provided options.
    /// </summary>
    /// <param name="options">
    ///     <see cref="CvesRequestOptions" />
    /// </param>
    /// <returns>
    ///     <see cref="CveResponse" />
    /// </returns>
    /// <exception cref="Exception">An exception is thrown if the API call fails</exception>
    /// <remarks>
    ///     To get All vulnerabilities, start by calling the API beginning with a startIndex of 0.
    ///     Successive requests should increment the startIndex by the value of resultsPerPage until
    ///     the response's startIndex has exceeded the value in totalResults.
    ///     <para>
    ///         After initial data population the last modified date parameters provide an efficient
    ///         way to update a user's local repository and stay within the API rate limits.
    ///         No more than once every two hours, automated requests should include a range where
    ///         lastModStartDate equals the time of the last record received from that and lastModEndDate
    ///         equals the current time.
    ///     </para>
    /// </remarks>
    public async Task<CveResponse?> GetCvesAsync(CvesRequestOptions options)
    {
        const string cveBaseUri = $"{BaseUri}cves/2.0?";
        List<string> queryStringParams = new();
        if (options.CpeName != null) queryStringParams.Add($"cpeName={HttpUtility.UrlEncode(options.CpeName)}");

        if (options.CveId != null) queryStringParams.Add($"cveId={HttpUtility.UrlEncode(options.CveId)}");

        if (options.CweId != null) queryStringParams.Add($"cweId={HttpUtility.UrlEncode(options.CweId)}");

        if (options.CvssV2Metrics != null) queryStringParams.Add($"cvssV2Metrics={HttpUtility.UrlEncode(options.CvssV2Metrics)}");

        if (options.CvssV2Severity != null) queryStringParams.Add($"cvssV2Severity={HttpUtility.UrlEncode(Helpers.Cvss2SeverityToString(options.CvssV2Severity))}");

        if (options.CvssV3Metrics != null) queryStringParams.Add($"cvssV3Metrics={HttpUtility.UrlEncode(options.CvssV3Metrics)}");

        if (options.CvssV3Severity != null) queryStringParams.Add($"cvssV3Severity={HttpUtility.UrlEncode(Helpers.Cvss3SeverityToString(options.CvssV3Severity))}");

        if (options.SourceIdentifier != null) queryStringParams.Add($"sourceIdentifier={HttpUtility.UrlEncode(options.SourceIdentifier)}");

        if (options.VirtualMatchString != null) queryStringParams.Add($"virtualMatchString={HttpUtility.UrlEncode(options.VirtualMatchString)}");

        if (options.VersionEnd != null) queryStringParams.Add($"versionEnd={HttpUtility.UrlEncode(options.VersionEnd)}");

        if (options.VersionEndType != null) queryStringParams.Add($"versionEndType={HttpUtility.UrlEncode(Helpers.VersionEndTypeToString(options.VersionEndType))}");

        if (options.VersionStart != null) queryStringParams.Add($"versionStart={HttpUtility.UrlEncode(options.VersionStart)}");

        if (options.VersionStartType != null) queryStringParams.Add($"versionStartType={HttpUtility.UrlEncode(Helpers.VersionStartTypeToString(options.VersionStartType))}");

        if (options.HasCertAlerts) queryStringParams.Add("hasCertAlerts");

        if (options.HasCertNotes) queryStringParams.Add("hasCertNotes");

        if (options.HasKev) queryStringParams.Add("hasKev");

        if (options.HasOval) queryStringParams.Add("hasOval");

        if (options.IsVulnerable) queryStringParams.Add("isVulnerable");

        if (options.KeywordExactMatch) queryStringParams.Add("keywordExactMatch");

        if (options.NoRejected) queryStringParams.Add("noRejected");

        if (!string.IsNullOrEmpty(options.KeywordSearch)) queryStringParams.Add($"keywordSearch={HttpUtility.UrlEncode(options.KeywordSearch)}");

        if (options.LastModStartDate != null) queryStringParams.Add($"lastModStartDate={HttpUtility.UrlEncode(((DateTime)options.LastModStartDate).ToString("O"))}");

        if (options.LastModEndDate != null) queryStringParams.Add($"lastModEndDate={HttpUtility.UrlEncode(((DateTime)options.LastModEndDate).ToString("O"))}");


        if (options.PubStartDate != null) queryStringParams.Add($"pubStartDate={HttpUtility.UrlEncode(((DateTime)options.PubStartDate).ToString("O"))}");


        if (options.PubEndDate != null) queryStringParams.Add($"pubEndDate={HttpUtility.UrlEncode(((DateTime)options.PubEndDate).ToString("O"))}");

        if (options.ResultsPerPage != null) queryStringParams.Add($"resultsPerPage={HttpUtility.UrlEncode(options.ResultsPerPage.ToString())}");

        if (options.StartIndex != null) queryStringParams.Add($"startIndex={HttpUtility.UrlEncode(options.StartIndex.ToString())}");

        var response = await _client.GetAsync(new Uri($"{cveBaseUri}{string.Join('&', queryStringParams)}"));
        var cveResponse = await response.Content.ReadFromJsonAsync<CveResponse>();

        if (cveResponse != null)
        {
            cveResponse.StatusCode = response.StatusCode;
            cveResponse.ReasonPhrase = response.ReasonPhrase;
        }
        
        return cveResponse;
    }
}