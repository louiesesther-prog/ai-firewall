# Builds store-ready ZIP packages for all browser variants.
# Usage:  powershell -ExecutionPolicy Bypass -File package-extensions.ps1
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$out  = Join-Path $root "dist"
if (!(Test-Path $out)) { New-Item -ItemType Directory -Path $out -Force | Out-Null }

$platforms = @{
  "chrome"  = @("extension")
  "edge"    = @("edge")
  "firefox" = @("firefox")
  "safari"  = @("safari")
}

# Files always shipped. test.html is dev-only, intentionally excluded.
$coreFiles = @("manifest.json","background.js","content.js","popup.html","popup.js","styles.css")

foreach ($p in $platforms.Keys) {
  $src = Join-Path $root $platforms[$p][0]
  $tmp = Join-Path $root "_tmp_$p"
  if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
  New-Item -ItemType Directory -Path $tmp -Force | Out-Null

  # Copy core files (only those that exist in this variant)
  foreach ($f in $coreFiles) {
    $fp = Join-Path $src $f
    if (Test-Path -LiteralPath $fp) { Copy-Item -LiteralPath $fp -Destination $tmp }
  }

  # Copy README / PRIVACY if present
  foreach ($md in @("README.md","PRIVACY.md")) {
    $mp = Join-Path $src $md
    if (Test-Path -LiteralPath $mp) { Copy-Item -LiteralPath $mp -Destination $tmp }
  }

  # Copy icons (PNG preferred for store; include SVG too)
  $icons = Join-Path $src "icons"
  if (Test-Path -LiteralPath $icons) {
    $icoDir = Join-Path $tmp "icons"
    New-Item -ItemType Directory -Path $icoDir -Force | Out-Null
    Get-ChildItem -Path $icons -File | Copy-Item -Destination $icoDir
  }

  $zip = Join-Path $out "ai-firewall-$p.zip"
  if (Test-Path -LiteralPath $zip) { Remove-Item -Force $zip }
  Compress-Archive -Path (Join-Path $tmp "*") -DestinationPath $zip
  Remove-Item -Recurse -Force $tmp

  $len = (Get-Item $zip).Length
  Write-Host "Created $zip ($([math]::Round($len/1KB)) KB)"
}

Write-Host "`nAll packages in: $out"