namespace NugetDefense.NVD.API;

/// <summary>
/// Options for the CVE API request
/// </summary>
public class CvesRequestOptions
{
    /// <summary>
    /// The exact value provided with cpeName is compared against the CPE Match Criteria within a CVE applicability statement. If the value of cpeName is considered to match, the CVE is included in the results.
    /// </summary>
    public string? CpeName;
    
    /// <summary>
    /// Returns a specific vulnerability identified by its unique Common Vulnerabilities and Exposures identifier
    /// </summary>
    public string? CveId;
    
    /// <summary>
    /// Returns only the CVEs that match the provided {CVSSv2 vector string}. Either full or partial vector strings may be used. This parameter cannot be used in requests that include <see cref="CvesRequestOptions.CvssV3Metrics"/>.
    /// NOTE: As of July 2022, the NVD no longer generates new information for CVSS v2. Existing CVSS v2 information will remain in the database but the NVD will no longer actively populate CVSS v2 for new CVEs. NVD analysts will continue to use the reference information provided with the CVE and any publicly available information at the time of analysis to associate Reference Tags, information related to CVSS v3.1, CWE, and CPE Applicability statements.
    /// </summary>
    public string? CvssV2Metrics;
    
    /// <summary>
    /// returns only the CVEs that match the provided CVSSv2 qualitative severity rating. This parameter cannot be used in requests that include <see cref="CvesRequestOptions.CvssV3Severity"/>
    /// </summary>
    public CvssV2Severity? CvssV2Severity;

    /// <summary>
    /// Returns only the CVEs that match the provided {CVSSv3 vector string}. Either full or partial vector strings may be used. This parameter cannot be used in requests that include <see cref="CvesRequestOptions.CvssV2Metrics"/>.
    /// </summary>
    public string? CvssV3Metrics;

    /// <summary>
    /// returns only the CVEs that match the provided CVSSv2 qualitative severity rating. This parameter cannot be used in requests that include <see cref="CvesRequestOptions.CvssV3Severity"/>
    /// </summary>
    public CvssV3Severity? CvssV3Severity;

    /// <summary>
    /// Returns only the CVE that include a weakness identified by Common Weakness Enumeration using the provided {CWE-ID}
    /// </summary>
    public string? CweId;

    /// <summary>
    /// Returns the CVE that contain a Technical Alert from US-CERT
    /// </summary>
    public bool HasCertAlerts;

    /// <summary>
    /// Returns the CVE that contain a Vulnerability Note from CERT/CC
    /// </summary>
    public bool HasCertNotes;

    /// <summary>
    /// Returns the CVE that appear in CISA's Known Exploited Vulnerabilities (KEV) Catalog
    /// </summary>
    public bool HasKev;

    /// <summary>
    /// Returns the CVE that contain information from MITRE's Open Vulnerability and Assessment Language (OVAL) before this transitioned to the Center for Internet Security (CIS)
    /// </summary>
    public bool HasOval;

    /// <summary>
    /// Returns only CVE associated with a specific CPE, where the CPE is also considered vulnerable. The exact value provided with cpeName is compared against the CPE Match Criteria within a CVE applicability statement. If the value of cpeName is considered to match, and is also considered vulnerable the CVE is included in the results.
    /// </summary>
    /// <remarks>
    /// <para>Requires: <see cref="CpeName"/></para>
    /// <para>NOTE: <see cref="VirtualMatchString"/> is not accepted when IsVulnerable is used.</para>
    /// </remarks>
    public bool IsVulnerable;

    /// <summary>
    /// By default, keywordSearch returns any CVE where a word or phrase is found in the current description.
    /// If the value of keywordSearch is a phrase, i.e., contains more than one term, including keywordExactMatch returns only the CVEs matching the phrase exactly. Otherwise, the results will contain records having any of the terms.
    /// </summary>
    /// <remarks>Requires: <see cref="KeywordSearch"/></remarks>
    public bool KeywordExactMatch;

    /// <summary>
    /// Returns only the CVEs where a word or phrase is found in the current description. Descriptions associated with CVE are maintained by the CVE Assignment Team through coordination with CVE Numbering Authorities (CNAs). The NVD has no control over CVE descriptions.
    /// </summary>
    /// <remarks>Multiple {keywords} function like an 'AND' statement. This returns results where all keywords exist somewhere in the current description, though not necessarily together.</remarks>
    /// <seealso cref="KeywordExactMatch"/>
    public string? KeywordSearch;

    /// <summary>
    /// Return only the CVEs that were last modified after the specified period.
    /// </summary>
    /// <remarks>
    /// Requires: <see cref="LastModEndDate"/>
    /// </remarks>
    public DateTime? LastModStartDate;
    
    /// <summary>
    /// Return only the CVEs that were last modified before the specified period.
    /// </summary>
    /// <remarks>Requires: <see cref="LastModStartDate"/></remarks>
    public DateTime? LastModEndDate;

    /// <summary>
    /// By default, the CVE API includes CVE records with the REJECT or Rejected status. When True, this excludes CVE records with the REJECT or Rejected status from API response.
    /// </summary>
    public bool NoRejected;

    /// <summary>
    /// Returns only the CVEs that were added to the NVD (i.e., published) after the specified date.
    /// </summary>
    /// <remarks>Requires: <see cref="PubEndDate"/></remarks>
    public DateTime? PubStartDate;
    
    /// <summary>
    /// Returns only the CVEs that were added to the NVD (i.e., published) before the specified date.
    /// </summary>
    /// <remarks>Requires: <see cref="PubStartDate"/></remarks>
    public DateTime? PubEndDate;

    /// <summary>
    /// Specifies the maximum number of CVE records to be returned in a single API response.
    /// </summary>
    /// <remarks>The default value and maximum allowable limit is 2,000</remarks>
    public int? ResultsPerPage;

    /// <summary>
    /// Specifies the index of the first CVE to be returned in the response data
    /// </summary>
    /// <remarks><para>The index is zero-based, meaning the first CVE is at index zero</para>
    ///<para>The CVE API returns four primary objects in the response body that are used for pagination: resultsPerPage, startIndex, totalResults, and vulnerabilities.
    /// totalResults indicates the total number of CVE records that match the request parameters.
    /// If the value of totalResults is greater than the value of resultsPerPage,
    /// there are more records than could be returned by a single API response and additional requests must update the startIndex to get the remaining records.
    /// </para>
    /// </remarks>
    /// <seealso cref="ResultsPerPage"/>
    public int? StartIndex;
    
    // TODO: Add a reference to the SourceAPI for SourceIdentifier below
    /// <summary>
    /// Returns CVE where the exact value of {sourceIdentifier} appears as a data source in the CVE record.
    /// </summary>
    /// <remarks>The CVE API returns {sourceIdentifier} values within the descriptions object.
    /// The Source API returns detailed information on the organizations that provide the data contained in the NVD dataset,
    /// including every valid {sourceIdentifier} value.
    /// </remarks>
    public string? SourceIdentifier;

    /// <summary>
    /// The <see cref="VirtualMatchString"/> parameter may be combined with versionEnd and <see cref="VersionEndType"/> to return only the CVEs associated with CPEs in specific version ranges.
    /// </summary>
    /// <remarks>
    /// Requires: <see cref="VersionEndType"/>
    /// </remarks>
    public string? VersionEnd;
    
    /// <summary>
    /// The <see cref="VirtualMatchString"/> parameter may be combined with versionEndType and <see cref="VersionEnd"/> to return only the CVEs associated with CPEs in specific version ranges.
    /// </summary>
    /// <remarks>
    /// Requires: <see cref="VersionEnd"/>
    /// </remarks>
    public VersionEndType? VersionEndType;
    
    /// <summary>
    /// The <see cref="VirtualMatchString"/> parameter may be combined with versionEnd and <see cref="VersionStartType"/> to return only the CVEs associated with CPEs in specific version ranges.
    /// </summary>
    /// <remarks>
    /// Requires: <see cref="VersionStartType"/>
    /// </remarks>
    public string? VersionStart;
    
    /// <summary>
    /// The <see cref="VirtualMatchString"/> parameter may be combined with versionEndType and <see cref="VersionStart"/> to return only the CVEs associated with CPEs in specific version ranges.
    /// </summary>
    /// <remarks>
    /// Requires: <see cref="VersionStart"/>
    /// </remarks>
    public VersionStartType? VersionStartType;
    
    /// <summary>
    /// Filters CVE more broadly than cpeName. The exact value of {cpe match string} is compared against the CPE Match Criteria present on CVE applicability statements.
    /// </summary>
    /// <remarks>
    /// CPE Match Criteria comes in two forms: CPE Match Strings and CPE Match String Ranges. Both are abstract concepts that are then correlated to CPE URIs in the Official CPE Dictionary. Unlike a CPE Name, match strings and match string ranges do not require a value in the part, vendor, product, or version components. The CVE API returns CPE Match Criteria within the configurations object.
    /// CPE Match String Ranges are only supported for the version component and only when VirtualMatchString is combined with <see cref="VersionStart"/>, <see cref="VersionStartType"/>, and/or <see cref="VersionEnd"/>, both <see cref="VersionEndType"/>.
    /// </remarks>
    /// <seealso cref="IsVulnerable"/>
    public string? VirtualMatchString;
} 