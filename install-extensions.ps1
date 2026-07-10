param(
  [switch]$Edge,
  [switch]$Firefox,
  [switch]$All
)

$root = "C:\Users\HP\ai-firewall"

function Find-Edge {
  $paths = @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe")
  foreach ($p in $paths) { if (Test-Path $p) { return $p } }
  return $null
}

function Find-Firefox {
  $paths = @("${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe", "$env:ProgramFiles\Mozilla Firefox\firefox.exe", "$env:LOCALAPPDATA\Mozilla Firefox\firefox.exe")
  foreach ($p in $paths) { if (Test-Path $p) { return $p } }
  return $null
}

function Install-ChromeLike {
  param($Exe, $Name, $ExtDir)
  Write-Host "Opening $Name with extension loaded..."
  Start-Process -FilePath $Exe -ArgumentList "--load-extension=`"$ExtDir`"", "edge://extensions/"
  Write-Host "`n$Name opened. In the extensions page:"
  Write-Host "  1. Enable 'Developer mode' (toggle at bottom-left)"
  Write-Host "  2. Verify 'AI Personal Firewall' shows as loaded"
  Write-Host "  3. Pin the extension to the toolbar (puzzle icon)"
}

function Install-Firefox {
  $exe = Find-Firefox
  if (-not $exe) { Write-Host "Firefox not found. Install from https://www.mozilla.org/firefox/"; return }
  Write-Host "Opening Firefox..."
  Start-Process -FilePath $exe -ArgumentList "-new-instance", "about:debugging#/runtime/this-firefox"
  Write-Host "`nIn the about:debugging page:"
  Write-Host "  1. Click 'Load Temporary Add-on...'"
  Write-Host "  2. Browse to: $root\firefox\manifest.json"
  Write-Host "  3. Click Open — extension loads until Firefox closes"
}

# ── Main ──────────────────────────────────────────────────
if ($Edge -or $All) {
  $exe = Find-Edge
  if ($exe) { Install-ChromeLike $exe "Edge" (Join-Path $root "extension") }
  else { Write-Host "Edge not found." }
}

if ($Firefox -or $All) {
  Install-Firefox
}

if (-not $Edge -and -not $Firefox -and -not $All) {
  Write-Host "Usage:"
  Write-Host "  .\install-extensions.ps1 -Edge     # Load in Edge"
  Write-Host "  .\install-extensions.ps1 -Firefox  # Load in Firefox"
  Write-Host "  .\install-extensions.ps1 -All      # Both"
}
