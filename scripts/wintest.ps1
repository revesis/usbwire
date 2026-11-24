# Windows client test: attach a remote FIDO key through usbwire + usbip-win2
# and time it with fidoping (CTAPHID_INIT, 1 KB CTAPHID_PING; no touch needed).
#
#   powershell -ExecutionPolicy Bypass -File wintest.ps1 -Server HOST:7443 [-OneWayMs 50] [-N 100] [-Extra "--no-push"]
#
# Run as Administrator (Windows only lets elevated processes open FIDO HID
# devices directly), from the folder holding usbwire-client.exe, fidoping.exe
# and udpdelay.exe. The client must already be paired with Server.
# -OneWayMs > 0 inserts udpdelay on 127.0.0.1:7444 for WAN emulation.
param(
    [Parameter(Mandatory = $true)][string]$Server,
    [int]$OneWayMs = 0,
    [int]$N = 100,
    [string]$Extra = ""
)
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$client = Join-Path $here "usbwire-client.exe"
$fidoping = Join-Path $here "fidoping.exe"
$log = Join-Path $env:TEMP "usbwire-wintest.log"

$target = $Server
$certArg = ""
$ud = $null
if ($OneWayMs -gt 0) {
    $safe = $Server -replace '[^A-Za-z0-9.-]', '_'
    $certArg = "--cert `"$env:APPDATA\usbwire\servers\$safe.der`""
    $ud = Start-Process -FilePath (Join-Path $here "udpdelay.exe") -ArgumentList "127.0.0.1:7444 $Server $OneWayMs" -PassThru -WindowStyle Hidden
    Start-Sleep -Milliseconds 300
    $target = "127.0.0.1:7444"
}

# FIDO devices present before we attach: the new one is ours.
$before = @(& $fidoping list)
$t0 = Get-Date
$p = Start-Process -FilePath $client -ArgumentList "serve --server $target $certArg --dev 1050:0407 --attach $Extra" `
    -RedirectStandardError $log -RedirectStandardOutput "$log.out" -PassThru -WindowStyle Hidden
try {
    do {
        Start-Sleep -Milliseconds 50
        $new = @(& $fidoping list) | Where-Object { $_ -match 'hid#' -and $_ -notin $before }
        if ($p.HasExited) { throw "usbwire-client exited; see $log" }
    } until ($new -or ((Get-Date) - $t0).TotalSeconds -gt 30)
    if (-not $new) { throw "no new FIDO device appeared within 30 s; see $log" }
    "remote key usable {0:N2} s after starting the client (added RTT: {1} ms)" -f ((Get-Date) - $t0).TotalSeconds, (2 * $OneWayMs)
    & $fidoping $new.Split('#')[2] -n $N
    if ($LASTEXITCODE -ne 0) { throw "fidoping failed" }
}
finally {
    Stop-Process -Id $p.Id -ErrorAction SilentlyContinue
    if ($ud) { Stop-Process -Id $ud.Id -ErrorAction SilentlyContinue }
    # The client logs to stdout; errors from main go to stderr.
    Get-Content $log, "$log.out" -ErrorAction SilentlyContinue | ForEach-Object { $_ -replace '\x1b\[[0-9;]*m', '' } | Select-String 'WARN|ERROR'
}
