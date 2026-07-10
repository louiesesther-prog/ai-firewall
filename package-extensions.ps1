$root = "C:\Users\HP\ai-firewall"
$out  = Join-Path $root "dist"
if (!(Test-Path $out)) { New-Item -ItemType Directory -Path $out -Force | Out-Null }

$platforms = @{
  "chrome"  = @("extension")
  "edge"    = @("edge")
  "firefox" = @("firefox")
  "safari"  = @("safari")
}

foreach ($p in $platforms.Keys) {
  $src = Join-Path $root $platforms[$p][0]
  $tmp = Join-Path $root "_tmp_$p"
  if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
  New-Item -ItemType Directory -Path $tmp -Force | Out-Null

  # Copy files preserving structure
  Copy-Item -Path (Join-Path $src "manifest.json") -Destination $tmp
  Copy-Item -Path (Join-Path $src "background.js")  -Destination $tmp
  Copy-Item -Path (Join-Path $src "content.js")     -Destination $tmp
  Copy-Item -Path (Join-Path $src "popup.html")     -Destination $tmp
  Copy-Item -Path (Join-Path $src "popup.js")       -Destination $tmp

  $css = Join-Path $src "styles.css"
  if (Test-Path $css) { Copy-Item -Path $css -Destination $tmp }

  $icons = Join-Path $src "icons"
  if (Test-Path $icons) {
    $icoDir = Join-Path $tmp "icons"
    New-Item -ItemType Directory -Path $icoDir -Force | Out-Null
    Get-ChildItem -Path $icons -Filter "*.svg" | Copy-Item -Destination $icoDir
  }

  $zip = Join-Path $out "ai-firewall-$p.zip"
  if (Test-Path $zip) { Remove-Item -Force $zip }
  Compress-Archive -Path (Join-Path $tmp "*") -DestinationPath $zip
  Remove-Item -Recurse -Force $tmp

  $len = (Get-Item $zip).Length
  Write-Host "Created $zip ($([math]::Round($len/1KB)) KB)"
}

Write-Host "`nAll packages in: $out"
