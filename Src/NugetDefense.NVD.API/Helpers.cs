namespace NugetDefense.NVD.API;

internal static class Helpers
{
    public static string Cvss2SeverityToString(CvssV2Severity? severity)
    {
        return severity switch
        {
            CvssV2Severity.Low => "LOW",
            CvssV2Severity.Medium => "MEDIUM",
            CvssV2Severity.High => "HIGH",
            _ => throw new ArgumentOutOfRangeException(nameof(severity), severity, null)
        };
    }

    public static string Cvss3SeverityToString(CvssV3Severity? severity)
    {
        return severity switch
        {
            CvssV3Severity.Low => "LOW",
            CvssV3Severity.Medium => "MEDIUM",
            CvssV3Severity.High => "HIGH",
            CvssV3Severity.Critical => "CRITICAL",
            _ => throw new ArgumentOutOfRangeException(nameof(severity), severity, null)
        };
    }

    public static string VersionEndTypeToString(VersionEndType? severity)
    {
        return severity switch
        {
            VersionEndType.Including => "including",
            VersionEndType.Excluding => "excluding",
            _ => throw new ArgumentOutOfRangeException(nameof(severity), severity, null)
        };
    }

    public static string VersionStartTypeToString(VersionStartType? severity)
    {
        return severity switch
        {
            VersionStartType.Including => "including",
            VersionStartType.Excluding => "excluding",
            _ => throw new ArgumentOutOfRangeException(nameof(severity), severity, null)
        };
    }
}