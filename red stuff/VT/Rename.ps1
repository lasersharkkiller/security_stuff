<#
.SYNOPSIS
  Recursively find files with no extension, query VirusTotal for file metadata,
  and rename (or copy) the file to include the suggested name/extension.

.DESCRIPTION
  For each file without an extension:
    - Compute SHA256
    - Call GET https://www.virustotal.com/api/v3/files/{sha256}
    - Prefer suggestions in this order:
        1. attributes.names (first entry)
        2. attributes.meaningful_name
        3. attributes.type_description (used as hint; extension inferred)
        4. attributes.mime_type (used as hint)
    - If a suggested filename/extension found, optionally rename (or copy)
      the file to the new name. If a file with the target name exists, an
      incremental suffix is added (safe rename).
    - Log actions to CSV and print a summary.

.PARAMETER SamplesFolder
  Root folder to search recursively.

.PARAMETER ApiKey
  VirusTotal API key. If omitted, will use $env:VT_API_KEY or prompt.

.PARAMETER OutLog
  Path to CSV log of operations (default: ./vt_rename_log.csv).

.PARAMETER DryRun
  If present, do not perform any renames or copies; only simulate and log.

.PARAMETER CopyInsteadOfRename
  If present, files will be copied to new names instead of renamed in-place.

.PARAMETER RateDelayMs
  Milliseconds to wait between VT API requests (default 600 ms — tune for your rate limits).

.PARAMETER Verbose
  Show detailed per-file output.

.EXAMPLE
  .\VT_Rename_NoExt_Files.ps1 -SamplesFolder "C:\samples" -DryRun

  # Actually rename:
  .\VT_Rename_NoExt_Files.ps1 -SamplesFolder "C:\samples" -ApiKey "xxxx" 

#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$SamplesFolder,

  [string]$ApiKey = $null,

  [string]$OutLog = ".\vt_rename_log.csv",

  [switch]$DryRun,

  [switch]$CopyInsteadOfRename,

  [int]$RateDelayMs = 600
)

Set-StrictMode -Version Latest

# -------------------- Helpers --------------------
function Get-VTApiKey {
  param([string]$KeyParam)
  if ($KeyParam) { return $KeyParam }
  if ($env:VT_API_KEY) { return $env:VT_API_KEY }
  return (Read-Host -Prompt 'Enter VirusTotal API key (input visible)')
}

function Compute-SHA256 {
  param([string]$FilePath)
  $sha = [System.Security.Cryptography.SHA256]::Create()
  $fs = [System.IO.File]::OpenRead($FilePath)
  try {
    $hashBytes = $sha.ComputeHash($fs)
    return ([BitConverter]::ToString($hashBytes)).Replace('-', '').ToLowerInvariant()
  } finally {
    $fs.Close()
    $sha.Dispose()
  }
}

function Safe-UniquePath {
  param([string]$DesiredPath)
  # If file exists, append suffix _1, _2, etc.
  $dir = [System.IO.Path]::GetDirectoryName($DesiredPath)
  $base = [System.IO.Path]::GetFileNameWithoutExtension($DesiredPath)
  $ext = [System.IO.Path]::GetExtension($DesiredPath)
  $candidate = $DesiredPath
  $i = 1
  while (Test-Path -LiteralPath $candidate) {
    $candidate = Join-Path $dir ("{0}_{1}{2}" -f $base, $i, $ext)
    $i++
    if ($i -gt 1000) { throw "Too many collisions creating unique name for $DesiredPath" }
  }
  return $candidate
}

function Query-VirusTotalFile {
  param(
    [string]$Sha256,
    [hashtable]$Headers,
    [int]$DelayMs = 0
  )
  $uri = "https://www.virustotal.com/api/v3/files/{0}" -f $Sha256
  try {
    $resp = Invoke-RestMethod -Method Get -Uri $uri -Headers $Headers -ErrorAction Stop
    if ($DelayMs -gt 0) { Start-Sleep -Milliseconds $DelayMs }
    return $resp
  } catch {
    if ($_.Exception -and $_.Exception.Response) {
      # If 404 or 403, return $null (not present / no access)
      try {
        $status = $_.Exception.Response.StatusCode.value__
      } catch { $status = $null }
      Write-Verbose ("VT query HTTP status: {0} for {1}" -f $status, $Sha256)
    }
    Write-Verbose ("VT query failed for {0} : {1}" -f $Sha256, $_.Exception.Message)
    return $null
  }
}

function Infer-FilenameFromVT {
  param([object]$VTResponse)
  # Preference order:
  # 1) attributes.names (array) -> first item
  # 2) attributes.meaningful_name
  # 3) attributes.type_description -> try to pick extension from that (e.g., "PE32 executable (GUI) (x86)")
  # 4) attributes.mime_type -> map common mimes to extensions
  if (-not $VTResponse) { return $null }

  $attr = $VTResponse.data.attributes

  # 1) names
  if ($attr.names -and $attr.names.Count -gt 0) {
    $firstName = $attr.names[0]
    if ($firstName -and ($firstName -match '\S')) {
      return [string]$firstName
    }
  }

  # 2) meaningful_name
  if ($attr.meaningful_name -and ($attr.meaningful_name -match '\S')) {
    return [string]$attr.meaningful_name
  }

  # 3) type_description -> infer extension heuristically
  if ($attr.type_description -and ($attr.type_description -match '\S')) {
    $td = [string]$attr.type_description
    # common heuristics
    if ($td -match 'PE32') { return "sample.exe" }
    if ($td -match 'MS-DOS') { return "sample.exe" }
    if ($td -match 'PDF') { return "sample.pdf" }
    if ($td -match 'Rich Text') { return "sample.rtf" }
    if ($td -match 'Zip archive') { return "sample.zip" }
    if ($td -match 'ELF') { return "sample.elf" }
    if ($td -match 'Java') { return "sample.jar" }
    # fallback to a generic name with no extension
    # we'll prefer mime_type next
  }

  # 4) mime_type -> simple mapping
  if ($attr.mime_type -and ($attr.mime_type -match '\S')) {
    $mt = [string]$attr.mime_type
    switch -regex ($mt) {
      'application\/x-dosexec' { return "sample.exe" }
      'application\/x-msdownload' { return "sample.exe" }
      'application\/pdf' { return "sample.pdf" }
      'application\/zip' { return "sample.zip" }
      'application\/x-java-archive' { return "sample.jar" }
      'application\/x-sh' { return "sample.sh" }
      'text\/plain' { return "sample.txt" }
      default { }
    }
  }

  return $null
}

# -------------------- Main --------------------
if (-not (Test-Path -LiteralPath $SamplesFolder)) {
  Write-Error ("SamplesFolder not found: {0}" -f $SamplesFolder)
  exit 1
}

$vtKey = Get-VTApiKey -KeyParam $ApiKey
if (-not $vtKey) {
  Write-Error 'No VirusTotal API key provided. Set the ApiKey param or $env:VT_API_KEY.'
  exit 1
}

$headers = @{ 'x-apikey' = $vtKey }

# Collect files with no extension
$files = Get-ChildItem -Path $SamplesFolder -File -Recurse |
  Where-Object { [string]::IsNullOrEmpty($_.Extension) -or $_.Extension -eq '' }

if ($files.Count -eq 0) {
  Write-Host "No files without extension found under $SamplesFolder"
  exit 0
}

Write-Host ("Found {0} files without extension under {1}" -f $files.Count, $SamplesFolder)

# Prepare log CSV
$logRows = @()

$renamed = 0
$skippedNotInVT = 0
$skippedNoSuggestion = 0
$errors = 0

$index = 0
foreach ($f in $files) {
  $index++
  Write-Host ("[{0}/{1}] Processing: {2}" -f $index, $files.Count, $f.FullName)
  try {
    $sha = Compute-SHA256 -FilePath $f.FullName

    # Query VT
    $vtResp = Query-VirusTotalFile -Sha256 $sha -Headers $headers -DelayMs $RateDelayMs
    if (-not $vtResp) {
      $skippedNotInVT++
      $logRows += [PSCustomObject]@{
        path = $f.FullName
        sha256 = $sha
        action = 'skipped_not_in_vt'
        suggested_name = ''
        final_path = ''
        note = 'no vt record / permission or api error'
      }
      continue
    }

    $suggested = Infer-FilenameFromVT -VTResponse $vtResp
    if (-not $suggested) {
      $skippedNoSuggestion++
      $logRows += [PSCustomObject]@{
        path = $f.FullName
        sha256 = $sha
        action = 'skipped_no_suggestion'
        suggested_name = ''
        final_path = ''
        note = 'vt returned no usable filename/extension hints'
      }
      continue
    }

    # Ensure suggested has name and extension; if not, try to add extension if it's "sample.exe" style
    $suggestedName = [System.IO.Path]::GetFileName($suggested)
    $suggestedExt = [System.IO.Path]::GetExtension($suggestedName)
    if (-not $suggestedExt -or $suggestedExt -eq '') {
      # if no ext, attempt to guess from mime/type_description via the Infer function already did some heuristics,
      # here we will leave it as-is (maybe add .bin)
      $suggestedName = $suggestedName + ".bin"
      $suggestedExt = ".bin"
    }

    # Build target full path in same directory as original file
    $targetPath = Join-Path $f.DirectoryName $suggestedName
    $targetPath = Safe-UniquePath -DesiredPath $targetPath

    # Perform rename or copy, obey DryRun
    if ($DryRun) {
      $logRows += [PSCustomObject]@{
        path = $f.FullName
        sha256 = $sha
        action = 'dryrun_proposed_rename'
        suggested_name = $suggestedName
        final_path = $targetPath
        note = 'dryrun only, no fs change'
      }
      Write-Host ("   DRYRUN -> would rename/copy to: {0}" -f $targetPath)
      $renamed++
    } else {
      if ($CopyInsteadOfRename) {
        Copy-Item -LiteralPath $f.FullName -Destination $targetPath -ErrorAction Stop
        $operation = 'copied'
      } else {
        Rename-Item -LiteralPath $f.FullName -NewName (Split-Path -Leaf $targetPath) -ErrorAction Stop
        # Rename-Item changes file in same directory; if targetPath was in same dir, this works
        $operation = 'renamed'
      }

      $logRows += [PSCustomObject]@{
        path = $f.FullName
        sha256 = $sha
        action = $operation
        suggested_name = $suggestedName
        final_path = $targetPath
        note = ''
      }
      Write-Host ("   {0} -> {1}" -f $operation, $targetPath)
      $renamed++
    }
  } catch {
    $errors++
    Write-Warning ("Error processing {0} : {1}" -f $f.FullName, $_.Exception.Message)
    $logRows += [PSCustomObject]@{
      path = $f.FullName
      sha256 = ($sha -or '')
      action = 'error'
      suggested_name = ''
      final_path = ''
      note = $_.Exception.Message
    }
  }
}

# write CSV log
$logDir = Split-Path -Parent (Resolve-Path -Path $OutLog)
if (-not (Test-Path -LiteralPath $logDir)) { New-Item -ItemType Directory -Path $logDir | Out-Null }
$logRows | Export-Csv -Path $OutLog -NoTypeInformation -Encoding UTF8

# summary
Write-Host ""
Write-Host ("Summary: processed {0} files. renamed/candidates: {1}. skipped_not_in_vt: {2}. skipped_no_suggestion: {3}. errors: {4}" -f $files.Count, $renamed, $skippedNotInVT, $skippedNoSuggestion, $errors)
Write-Host ("Log written to: {0}" -f (Resolve-Path -Path $OutLog))
