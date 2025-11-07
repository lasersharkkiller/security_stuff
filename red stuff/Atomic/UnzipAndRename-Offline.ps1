<#
.SYNOPSIS
  Offline sandbox helper: unzip a password-protected archive, hash, detect type by magic bytes
  (with PE EXE/DLL parsing + entry point RVA), rename to <sha256>.<ext>, and write a manifest.
  Optionally re-zip the renamed set with a password (offline, via 7-Zip).

.PARAMETERS
  -ZipPath         Path to the password-protected zip (from VT or anywhere)
  -ZipPassword     Zip password (default: 'infected')
  -OutputDir       Destination directory for extracted & renamed files
  -SevenZipPath    Full path to 7z.exe if not on PATH
  -Rezip           If set, creates a new password-protected zip of the renamed files
  -RezipPassword   Password for the new zip (default: 'infected')

.OUTPUTS
  <OutputDir>\_rename_manifest.csv  (old_name,new_name,sha256,detected_type,is_dll,entry_point_rva)

.NOTES
  - Entirely offline; no VirusTotal/API calls.
  - Treat files as malicious. Use a throwaway VM.
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [string]$ZipPath,

  [string]$ZipPassword = "infected",

  [string]$OutputDir = ".\unzipped_renamed",

  [string]$SevenZipPath = "",

  [switch]$Rezip,

  [string]$RezipPassword = "infected"
)

# ---------------- Utilities ----------------
function Get-7zPath {
  param([string]$Hint)
  if ($Hint -and (Test-Path $Hint)) { return (Resolve-Path $Hint).Path }
  $cmd = Get-Command "7z.exe" -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  throw "7z.exe not found. Install 7-Zip or pass -SevenZipPath."
}

function Read-Bytes {
  param([string]$FilePath, [int]$Count = 4096, [int64]$Offset = 0)
  $fs = [System.IO.File]::Open($FilePath, 'Open', 'Read', 'ReadWrite')
  try {
    if ($Offset -gt 0) { $fs.Seek($Offset, 'Begin') | Out-Null }
    $buf = New-Object byte[] $Count
    $read = $fs.Read($buf, 0, $Count)
    if ($read -lt $Count) { $buf = $buf[0..($read-1)] }
    return ,$buf
  } finally { $fs.Dispose() }
}

function Get-PEInfo {
  param([string]$FilePath)
  # Returns @{ IsPE=bool; IsDLL=bool; EntryPointRVA=uint?; Machine=string; Bitness="32"/"64"/$null }
  $info = @{
    IsPE = $false; IsDLL = $false; EntryPointRVA = $null; Machine = $null; Bitness = $null
  }
  $dos = Read-Bytes -FilePath $FilePath -Count 0x100 # 256 bytes is enough for e_lfanew
  if ($dos.Length -lt 0x40) { return $info }
  if (!($dos[0] -eq 0x4D -and $dos[1] -eq 0x5A)) { return $info } # 'MZ'
  try {
    $e_lfanew = [BitConverter]::ToInt32($dos, 0x3C)
  } catch { return $info }

  # Read PE signature + IMAGE_FILE_HEADER (24 bytes total: 4 + 20)
  $peHdr = Read-Bytes -FilePath $FilePath -Offset $e_lfanew -Count 24
  if ($peHdr.Length -lt 24) { return $info }
  if (!($peHdr[0] -eq 0x50 -and $peHdr[1] -eq 0x45 -and $peHdr[2] -eq 0x00 -and $peHdr[3] -eq 0x00)) { return $info } # 'PE\0\0'
  $info.IsPE = $true

  # IMAGE_FILE_HEADER fields
  $Machine = [BitConverter]::ToUInt16($peHdr, 4)
  $SizeOpt = [BitConverter]::ToUInt16($peHdr, 20 - 2) # at offset 20? Wait: header is 20 bytes after PE sig; SizeOfOptionalHeader at offset 16 within header. We'll compute robustly below.
  # More robustly read from the full 20 bytes:
  $imageFileHeader = Read-Bytes -FilePath $FilePath -Offset ($e_lfanew + 4) -Count 20
  $machineVal = [BitConverter]::ToUInt16($imageFileHeader, 0)
  $sizeOfOptionalHeader = [BitConverter]::ToUInt16($imageFileHeader, 16)
  $characteristics = [BitConverter]::ToUInt16($imageFileHeader, 18)

  switch ($machineVal) {
    0x014c { $info.Machine = "I386";  $info.Bitness = "32" }
    0x8664 { $info.Machine = "AMD64"; $info.Bitness = "64" }
    default { $info.Machine = ("0x{0:X4}" -f $machineVal) }
  }

  if ($characteristics -band 0x2000) { $info.IsDLL = $true } # IMAGE_FILE_DLL

  # Read Optional Header (need AddressOfEntryPoint at offset 0x10 within it)
  if ($sizeOfOptionalHeader -gt 0) {
    $opt = Read-Bytes -FilePath $FilePath -Offset ($e_lfanew + 4 + 20) -Count ([Math]::Min($sizeOfOptionalHeader, 256))
    if ($opt.Length -ge 0x18) {
      # PE32: Magic 0x10B; PE32+: 0x20B. AddressOfEntryPoint is at +0x10 for both.
      $ep = [BitConverter]::ToUInt32($opt, 0x10)
      $info.EntryPointRVA = $ep
      # Bitness already set above; keep as-is.
    }
  }
  return $info
}

function Detect-TypeAndExt {
  param([string]$FilePath)
  # Returns @{ type="PE32 EXE"/"PE32 DLL"/"PDF"/"ZIP"/"ELF"/"PNG"/"JPG"/"Unknown"; ext=".exe"/".dll"/... }
  $r = @{ type = "Unknown"; ext = "" }

  # Read first 8 bytes to catch many formats fast
  $head = Read-Bytes -FilePath $FilePath -Count 64
  if ($head.Length -ge 4) {
    # PDF: %PDF
    if ($head[0] -eq 0x25 -and $head[1] -eq 0x50 -and $head[2] -eq 0x44 -and $head[3] -eq 0x46) { $r.type="PDF"; $r.ext=".pdf"; return $r }
    # ZIP family (ZIP/JAR/APK): PK\x03\x04
    if ($head[0] -eq 0x50 -and $head[1] -eq 0x4B -and $head[2] -eq 0x03 -and $head[3] -eq 0x04) { $r.type="ZIP"; $r.ext=".zip"; return $r }
    # ELF: 0x7F 'E' 'L' 'F'
    if ($head.Length -ge 4 -and $head[0] -eq 0x7F -and $head[1] -eq 0x45 -and $head[2] -eq 0x4C -and $head[3] -eq 0x46) { $r.type="ELF"; $r.ext=".elf"; return $r }
    # PNG
    if ($head.Length -ge 8 -and ($head[0..7] -join ',') -eq "137,80,78,71,13,10,26,10") { $r.type="PNG"; $r.ext=".png"; return $r }
    # JPG
    if ($head[0] -eq 0xFF -and $head[1] -eq 0xD8) { $r.type="JPG"; $r.ext=".jpg"; return $r }
    # PE (MZ) → deep check
    if ($head[0] -eq 0x4D -and $head[1] -eq 0x5A) {
      $pe = Get-PEInfo -FilePath $FilePath
      if ($pe.IsPE) {
        if ($pe.IsDLL) { $r.type = "PE DLL"; $r.ext = ".dll" }
        else { $r.type = "PE EXE"; $r.ext = ".exe" }
        $r.EntryPointRVA = $pe.EntryPointRVA
        return $r
      }
      # If MZ but not valid PE header in range, still call it PE/Unknown
      $r.type="PE (unknown)"; $r.ext=".exe"; return $r
    }
  }
  return $r
}

function Sanitize-Name([string]$s) {
  $bad = [IO.Path]::GetInvalidFileNameChars()
  foreach ($c in $bad) { $s = $s -replace [Regex]::Escape($c), "_" }
  $s.TrimEnd('.',' ')
}

# ---------------- Unzip ----------------
$seven = Get-7zPath -Hint $SevenZipPath
if (-not (Test-Path $ZipPath)) { throw "ZIP not found: $ZipPath" }
if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir | Out-Null }

Write-Host "Extracting -> $OutputDir" -ForegroundColor Cyan
$extractArgs = @("x", "-p$ZipPassword", "-y", "-o$((Resolve-Path $OutputDir).Path)", (Resolve-Path $ZipPath).Path)
$proc = Start-Process -FilePath $seven -ArgumentList $extractArgs -NoNewWindow -Wait -PassThru
if ($proc.ExitCode -ne 0) { throw "7z extraction failed with exit code $($proc.ExitCode)." }

# ---------------- Rename pass (offline) ----------------
$files = Get-ChildItem -Path $OutputDir -File -Recurse
if ($files.Count -eq 0) { Write-Host "No files extracted."; return }

$manifest = New-Object System.Collections.Generic.List[object]

foreach ($f in $files) {
  try {
    $sha = (Get-FileHash -Path $f.FullName -Algorithm SHA256).Hash.ToLower()
  } catch {
    Write-Warning "Hash failed for $($f.FullName): $_"
    continue
  }

  $det = Detect-TypeAndExt -FilePath $f.FullName
  $ext = $det.ext
  $type = $det.type
  $isDll = $false
  $entryRVA = $null
  if ($type -like "PE DLL") { $isDll = $true }
  if ($det.ContainsKey("EntryPointRVA")) { $entryRVA = $det.EntryPointRVA }

  $newName = "$sha$ext"
  $newName = Sanitize-Name $newName

  # Ensure uniqueness in case of duplicates
  $dest = Join-Path $f.DirectoryName $newName
  $i = 1
  while (Test-Path $dest) {
    $dest = Join-Path $f.DirectoryName ("{0}_{1}{2}" -f $sha, $i, $ext)
    $i++
  }

  try {
    if ($dest -ne $f.FullName) { Move-Item -Path $f.FullName -Destination $dest -Force }
  } catch {
    Write-Warning "Rename failed $($f.Name) -> $([IO.Path]::GetFileName($dest)): $_"
    continue
  }

  $manifest.Add([PSCustomObject]@{
    old_name          = $f.Name
    new_name          = [IO.Path]::GetFileName($dest)
    sha256            = $sha
    detected_type     = $type
    is_dll            = $isDll
    entry_point_rva   = $entryRVA
  })
}

# Write manifest
$csvPath = Join-Path $OutputDir "_rename_manifest.csv"
$manifest | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
Write-Host "Manifest: $((Resolve-Path $csvPath).Path)" -ForegroundColor Green

# ---------------- Optional re-zip ----------------
if ($Rezip) {
  $rezipPath = Join-Path (Split-Path -Path $OutputDir -Parent) ((Split-Path -Leaf $OutputDir) + "_renamed.zip")
  Write-Host "Re-zipping renamed files -> $rezipPath" -ForegroundColor Cyan
  # 7z a -tzip out.zip <OutputDir>\* -pPASSWORD -mem=AES256 -y
  $addArgs = @("a", "-tzip", (Resolve-Path $rezipPath).Path, (Join-Path (Resolve-Path $OutputDir).Path "*"), "-p$RezipPassword", "-mem=AES256", "-y")
  $p2 = Start-Process -FilePath $seven -ArgumentList $addArgs -NoNewWindow -Wait -PassThru
  if ($p2.ExitCode -ne 0) { Write-Warning "Re-zip failed with exit code $($p2.ExitCode)." }
  else { Write-Host "Created: $rezipPath" -ForegroundColor Green }
}

Write-Host "Done." -ForegroundColor Cyan
