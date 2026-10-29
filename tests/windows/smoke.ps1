# Smoke test of the Windows engine (WinDivert) on a CI runner.
# Needs Administrator, build\geneva.exe with WinDivert.dll and WinDivert64.sys
# next to it, and HTTP access to example.com.
#
#   pwsh tests/windows/smoke.ps1 [-Bin build\geneva.exe]
param([string]$Bin = "build\geneva.exe")

$ErrorActionPreference = "Stop"
$Bin = (Resolve-Path $Bin).Path
$Work = Join-Path ([IO.Path]::GetTempPath()) ("geneva-smoke-" + [guid]::NewGuid())
New-Item -ItemType Directory $Work | Out-Null
$Events = Join-Path $Work "events.jsonl"
$Log = Join-Path $Work "engine.log"
$Ctl = "tcp:127.0.0.1:47123"
$Url = "http://example.com/"
$script:Failed = 0

function Ok($name) { Write-Host "  ok   $name" }
function Fail($name) { Write-Host "  FAIL $name"; $script:Failed++ }
function Check($cond, $name) { if ($cond) { Ok $name } else { Fail $name } }

function Fetch([int]$timeout = 10) {
    $code = & curl.exe -s -o NUL -w "%{http_code}" --max-time $timeout $Url
    return "$code"
}

function Ctl([string[]]$cmdArgs) {
    $out = & $Bin ctl -c $Ctl @cmdArgs
    if ($LASTEXITCODE -ne 0) { Write-Host "geneva ctl $cmdArgs -> exit $LASTEXITCODE`: $out" }
    return ($out | Select-Object -Last 1) | ConvertFrom-Json
}

function Events() {
    if (!(Test-Path $Events)) { return @() }
    return Get-Content $Events | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json }
}

function Wait-Event([string]$ev, [int]$seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        if (Events | Where-Object { $_.ev -eq $ev }) { return $true }
        Start-Sleep -Milliseconds 200
    }
    return $false
}

Write-Host "geneva: $(& $Bin version)"
Check ((Fetch) -match '^[23]') "example.com answers without the engine"

# Duplicate every SYN, the copy with window 7: a harmless change that shows
# both the verdict path and injection work. Windows may negotiate ECN, and
# then its SYNs carry flags SEC, so each strategy has a tree for both.
$strategy = '[TCP:flags:S]-duplicate(tamper{TCP:window:replace:7},)-|[TCP:flags:SEC]-duplicate(tamper{TCP:window:replace:7},)-| \/'
$p = Start-Process -FilePath $Bin -PassThru -NoNewWindow -ArgumentList @(
    "run", "-s", "`"$strategy`"", "-p", "80", "-c", $Ctl, "-e", "`"$Events`"",
    "--stats-interval", "1", "-v", "--log-file", "`"$Log`"")
try {
    Check (Wait-Event "ready" 20) "engine is ready"
    $st = Ctl @("status")
    Check ($st.ok -and $st.backend -eq "windivert") "status: backend windivert"
    Check ($st.firewall -eq "windivert") "status: capture by windivert"

    Check ((Fetch) -match '^[23]') "HTTP works through the engine"
    Check ((Fetch) -match '^[23]') "HTTP works through the engine again"
    $s = Ctl @("stats")
    Check ($s.pkts_out -gt 0 -and $s.pkts_in -gt 0) "packets captured both ways ($($s.pkts_out) out, $($s.pkts_in) in)"
    Check ($s.triggered -ge 2) "SYN tree fired ($($s.triggered))"
    Check ($s.injected -ge 2) "duplicates injected ($($s.injected))"
    Check ($s.send_errors -eq 0 -and $s.verdict_errors -eq 0) "no send or verdict errors"

    # Dropping every SYN must break HTTP: proof that the capture is in path.
    $r = Ctl @("set_strategy", 'strategy=[TCP:flags:S]-drop-|[TCP:flags:SEC]-drop-| \/')
    Check $r.ok "set_strategy drop"
    Check ((Fetch 5) -notmatch '^[23]') "HTTP fails while SYNs are dropped"
    $r = Ctl @("pause")
    Check ((Fetch) -match '^[23]') "HTTP works while paused"
    $r = Ctl @("resume")
    $r = Ctl @("set_strategy", "strategy=\/")
    Check ((Fetch) -match '^[23]') "HTTP works with the empty strategy"

    $r = Ctl @("stop")
    Check $r.ok "stop"
    Check ($p.WaitForExit(15000)) "engine exits"
    Check ($p.ExitCode -eq 0) "exit code 0 (got $($p.ExitCode))"
    $exit = Events | Where-Object { $_.ev -eq "exit" }
    Check ($exit -and $exit.reason -eq "control") "exit event, reason control"
    Check ((Fetch) -match '^[23]') "HTTP works after the engine is gone"
} finally {
    if (!$p.HasExited) { $p.Kill(); $p.WaitForExit() }
    if ($script:Failed) {
        Write-Host "---- engine log"; if (Test-Path $Log) { Get-Content $Log | Select-Object -Last 150 }
        Write-Host "---- tcp settings"; netsh int tcp show global
        Write-Host "---- events"; if (Test-Path $Events) { Get-Content $Events | Select-Object -Last 30 }
    }
}

# A missing driver must be a clear error, not a crash.
$bare = Join-Path $Work "bare"
New-Item -ItemType Directory $bare | Out-Null
Copy-Item $Bin $bare
& (Join-Path $bare "geneva.exe") run -s '\/' -p 80 --duration 1 2>&1 | Out-Null
Check ($LASTEXITCODE -eq 1) "no WinDivert.dll: exit 1 (got $LASTEXITCODE)"

if ($script:Failed) { Write-Host "smoke: $script:Failed failed"; exit 1 }
Write-Host "smoke: all passed"
