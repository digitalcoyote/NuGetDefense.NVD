$content = Get-Content './Src/NuGetDefense.NVD/NuGetDefense.NVD.nuspec'
$Regex = [Regex]::new('(?<=<version>)(\d{0,4}\.\d{0,4}\.\d{0,4}\.{0,1}\d{0,4})(?=<\/version>)')           
$Match = $Regex.Match($content)           
$oldVersion = $Match.Value

$VersionPieces = $oldVersion.Split('.')
$Version = "$($VersionPieces[0]).$($VersionPieces[1]).$($VersionPieces[2]).$([int]$VersionPieces[3] + 1)"
$updatedNuspec = $content.Replace("<version>$oldVersion</version>", "<version>$Version</version>")
Set-Content './Src/NuGetDefense.NVD/NuGetDefense.NVD.nuspec' $updatedNuspec

dotnet restore ./Src/NVDFeedImporter/NVDFeedImporter.csproj 
dotnet build -c Release ./Src/NVDFeedImporter/NVDFeedImporter.csproj
dotnet ./Src/NVDFeedImporter/bin/Release/netcoreapp3.1/NVDFeedImporter.dll

$destination = './Src/NuGetDefense.NVD/bin/Release/netstandard2.0/'

if(!(Test-Path $destination))
{
    New-Item -Path $destination -ItemType Directory -Force | Out-Null
}

$MoveBinArgs = @{
    Path = 'VulnerabilityData.bin'
    Destination = $destination
    Force = $true
}

Move-Item @MoveBinArgs
dotnet build -c Release ./Src/NuGetDefense.NVD/NuGetDefense.NVD.csproj
dotnet pack -c Release ./Src/NuGetDefense.NVD/NuGetDefense.NVD.csproj