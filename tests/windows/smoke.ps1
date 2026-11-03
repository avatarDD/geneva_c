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

function Eval([string[]]$evalArgs) {
    $out = & $Bin eval --host example.com --timeout 5 -l warn @evalArgs 2>&1
    Write-Host "    eval $evalArgs -> exit $LASTEXITCODE`: $($out -join ' | ')"
    return $LASTEXITCODE
}

# ---- 1.1: an external WinDivert filter (--filter, set_filter, --first) ----

function Get-V4([string]$name) {
    try {
        return @([System.Net.Dns]::GetHostAddresses($name) |
            Where-Object { $_.AddressFamily -eq 'InterNetwork' } | ForEach-Object { $_.IPAddressToString })
    } catch { return @() }
}
# Two addresses that serve HTTP: A (example.com) and B (another address).
$A = (Get-V4 "example.com")[0]
$HostA = "example.com"
$B = $null; $HostB = $null
foreach ($n in @("example.com", "example.org", "example.net", "iana.org")) {
    $other = Get-V4 $n | Where-Object { $_ -ne $A } | Select-Object -First 1
    if ($other) { $B = $other; $HostB = $n; break }
}
Write-Host "addresses: A $A ($HostA), B $B ($HostB)"

function FetchAt([string]$ip, [string]$name, [int]$timeout = 10, [int]$times = 1) {
    $urls = @(); for ($i = 0; $i -lt $times; $i++) { $urls += "http://$name/" }
    $codes = & curl.exe -s -o NUL -w "%{http_code} " --max-time $timeout --resolve "${name}:80:$ip" @urls
    return "$codes".Trim()
}
function FilterFor([string]$ip) {
    return "(outbound and ip.DstAddr == $ip and tcp.DstPort == 80) or (inbound and ip.SrcAddr == $ip and tcp.SrcPort == 80)"
}
function Start-Engine([string[]]$engArgs, [string]$ev, [string]$log) {
    if (Test-Path $ev) { Remove-Item $ev }
    $script:Events = $ev
    return Start-Process -FilePath $Bin -PassThru -NoNewWindow -ArgumentList (@("run") + $engArgs + @(
        "-e", "`"$ev`"", "--stats-interval", "1", "-v", "--log-file", "`"$log`""))
}

$feat = (& $Bin version --json | ConvertFrom-Json).features
Check (($feat -contains "filter") -and ($feat -contains "set_filter") -and ($feat -contains "first")) "version: features filter, set_filter, first"

# a filter that does not compile: exit 2, error event with the position
$EvBad = Join-Path $Work "bad.jsonl"
& $Bin run -s '\/' -p 80 --filter "tcp.DstPort == 80 and and" -e $EvBad --duration 2 2>&1 | Out-Null
Check ($LASTEXITCODE -eq 2) "bad --filter: exit 2 (got $LASTEXITCODE)"
$err = Get-Content $EvBad | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object { $_.ev -eq "error" }
Check ($err -and $err.where -eq "filter" -and $null -ne $err.pos) "bad --filter: error event with where filter and pos"

if (!$A -or !$B) {
    Fail "need two HTTP addresses for the filter tests"
} else {
    $Events1 = Join-Path $Work "filter.jsonl"
    $Log1 = Join-Path $Work "filter.log"
    $p = Start-Engine @("-s", "`"$strategy`"", "-p", "80", "-c", $Ctl, "--filter", "`"$(FilterFor $A)`"") $Events1 $Log1
    try {
        Check (Wait-Event "ready" 20) "filter: engine is ready"
        $fev = Events | Where-Object { $_.ev -eq "filter" } | Select-Object -First 1
        Check ($fev -and $fev.source -eq "start" -and $fev.filter -like "*$A*and not loopback") "filter event at start"
        $st = Ctl @("status")
        Check ($st.filter -like "(*$A*) and not loopback") "status.filter"

        $s0 = Ctl @("stats")
        Check ((FetchAt $A $HostA) -match '^[23]') "filter: HTTP to A works"
        $s1 = Ctl @("stats")
        Check ($s1.triggered -gt $s0.triggered) "filter: SYN to A duplicated ($($s0.triggered) -> $($s1.triggered))"
        Check ((FetchAt $B $HostB) -match '^[23]') "filter: HTTP to B works"
        $s2 = Ctl @("stats")
        Check ($s2.triggered -eq $s1.triggered -and $s2.pkts_out -eq $s1.pkts_out) "filter: B is not captured"

        # set_filter to B while a connection to A is open: it goes on
        $c = New-Object Net.Sockets.TcpClient
        $c.Connect($A, 80)
        $ns = $c.GetStream()
        $ns.ReadTimeout = 10000
        $part = [Text.Encoding]::ASCII.GetBytes("GET / HTTP/1.1`r`nHost: $HostA`r`n")
        $ns.Write($part, 0, $part.Length)
        $r = Ctl @("set_filter", "filter=$(FilterFor $B)")
        Check ($r.ok -and $r.filter -like "*$B*and not loopback") "set_filter to B"
        Start-Sleep -Milliseconds 500
        $rest = [Text.Encoding]::ASCII.GetBytes("Connection: close`r`n`r`n")
        $ns.Write($rest, 0, $rest.Length)
        $buf = New-Object byte[] 65536
        $got = ""
        try {
            while ($true) { $n = $ns.Read($buf, 0, $buf.Length); if ($n -le 0) { break }; $got += [Text.Encoding]::ASCII.GetString($buf, 0, $n) }
        } catch { Write-Host "    read: $_" }
        $c.Close()
        Check ($got -match '^HTTP/1\.[01] [23]') "the open connection to A survives set_filter"
        $fev = Events | Where-Object { $_.ev -eq "filter" -and $_.source -eq "set_filter" }
        Check ($fev) "filter event after set_filter"
        $s3 = Ctl @("stats")
        Check ((FetchAt $B $HostB) -match '^[23]') "set_filter: HTTP to B works"
        $s4 = Ctl @("stats")
        Check ($s4.triggered -gt $s3.triggered) "set_filter: SYN to B duplicated"
        Check ((FetchAt $A $HostA) -match '^[23]') "set_filter: HTTP to A works"
        $s5 = Ctl @("stats")
        Check ($s5.triggered -eq $s4.triggered) "set_filter: A is not captured any more"

        # a bad expression is refused with its position; the filter stays
        $r = Ctl @("set_filter", "filter=tcp.DstPort == 80 and and")
        Check (!$r.ok -and $null -ne $r.pos) "bad set_filter: ok false with pos ($($r.error))"
        $st = Ctl @("status")
        Check ($st.filter -like "*$B*") "bad set_filter: the filter stays"
        $r = Ctl @("reload_filter")
        Check (!$r.ok) "reload_filter without --filter-file: ok false"

        # a second instance with a disjoint filter works next to the first
        $Ctl2 = "tcp:127.0.0.1:47124"
        $Events2 = Join-Path $Work "second.jsonl"
        $p2 = Start-Process -FilePath $Bin -PassThru -NoNewWindow -ArgumentList @(
            "run", "-s", "`"$strategy`"", "-p", "80", "-c", $Ctl2, "--filter", "`"$(FilterFor $A)`"",
            "-e", "`"$Events2`"", "--log-file", "`"$(Join-Path $Work 'second.log')`"")
        try {
            $deadline = (Get-Date).AddSeconds(20)
            while ((Get-Date) -lt $deadline -and !((Test-Path $Events2) -and (Select-String -Quiet -Path $Events2 -Pattern '"ev":"ready"'))) { Start-Sleep -Milliseconds 200 }
            $t0 = (& $Bin ctl -c $Ctl2 stats | Select-Object -Last 1 | ConvertFrom-Json)
            $u0 = Ctl @("stats")
            Check ((FetchAt $A $HostA) -match '^[23]' -and (FetchAt $B $HostB) -match '^[23]') "two instances: HTTP to A and B works"
            $t1 = (& $Bin ctl -c $Ctl2 stats | Select-Object -Last 1 | ConvertFrom-Json)
            $u1 = Ctl @("stats")
            Check ($t1.triggered -gt $t0.triggered) "two instances: the second one handles A"
            Check ($u1.triggered -gt $u0.triggered) "two instances: the first one handles B"
            & $Bin ctl -c $Ctl2 stop | Out-Null
            Check ($p2.WaitForExit(15000) -and $p2.ExitCode -eq 0) "two instances: the second one stops"
        } finally {
            if (!$p2.HasExited) { $p2.Kill(); $p2.WaitForExit() }
        }
        $r = Ctl @("stop")
        Check ($p.WaitForExit(15000) -and $p.ExitCode -eq 0) "filter: engine exits with 0"
    } finally {
        if (!$p.HasExited) { $p.Kill(); $p.WaitForExit() }
        if ($script:Failed) { Write-Host "---- filter engine log"; if (Test-Path $Log1) { Get-Content $Log1 | Select-Object -Last 80 } }
    }

    # --first 3: one long keep-alive flow (many requests on one connection);
    # the strategy fires on every outbound packet with ACK, but only within
    # the first 3 packets of the flow
    $Events3 = Join-Path $Work "first.jsonl"
    $Log3 = Join-Path $Work "first.log"
    $p = Start-Engine @("-s", "`"[TCP:flags:A*]-duplicate-| \/`"", "-p", "80", "-c", $Ctl,
        "--filter", "`"$(FilterFor $A)`"", "--first", "3") $Events3 $Log3
    try {
        Check (Wait-Event "ready" 20) "--first: engine is ready"
        $codes = FetchAt $A $HostA 30 20
        Check ($codes -match '^([23]\d\d ?){20}$') "--first: 20 requests on one connection work ($codes)"
        $s = Ctl @("stats")
        Check ($s.triggered -ge 1 -and $s.triggered -le 3) "--first: the strategy fired at most 3 times ($($s.triggered))"
        Check ($s.passed_first -gt 0) "--first: later packets passed ($($s.passed_first))"
        Check ($s.pkts_out -le 3 -and $null -ne $s.flow_evictions) "--first: only the first packets counted ($($s.pkts_out) out)"
        $r = Ctl @("stop")
        Check ($p.WaitForExit(15000) -and $p.ExitCode -eq 0) "--first: engine exits with 0"
    } finally {
        if (!$p.HasExited) { $p.Kill(); $p.WaitForExit() }
        if ($script:Failed) { Write-Host "---- --first engine log"; if (Test-Path $Log3) { Get-Content $Log3 | Select-Object -Last 60 } }
    }
    $script:Events = $null

    # the evaluator's --filter narrows its slots
    Check ((Eval @("--ip", $A, "--filter", "ip.DstAddr == $A or ip.SrcAddr == $A",
        '-s', '[TCP:flags:S]-drop-|[TCP:flags:SEC]-drop-| \/')) -eq 1) "eval --filter on A: dropping SYNs to A fails"
    Check ((Eval @("--ip", $A, "--filter", "ip.DstAddr == $B or ip.SrcAddr == $B",
        '-s', '[TCP:flags:S]-drop-|[TCP:flags:SEC]-drop-| \/')) -eq 0) "eval --filter on B: A is not touched"
    Check ((Fetch) -match '^[23]') "HTTP works after the filter tests"
}

# The evaluator: probes from its own port block, strategies through the
# embedded engine (geneva eval prints "fitness<TAB>strategy").
Check ((Eval @("--no-engine")) -eq 0) "eval: http baseline succeeds"
Check ((Eval @("--probe", "tls", "--no-engine")) -eq 0) "eval: tls baseline succeeds"
Check ((Eval @('-s', '[TCP:flags:S]-duplicate-|[TCP:flags:SEC]-duplicate-| \/')) -eq 0) "eval: harmless strategy succeeds"
Check ((Eval @('-s', '[TCP:flags:S]-drop-|[TCP:flags:SEC]-drop-| \/')) -eq 1) "eval: dropping SYNs fails"
Check ((Eval @("--probe", "exec", "--timeout", "15", "--cmd",
    'curl.exe -s -o NUL --max-time 5 --local-port {lports} http://example.com/',
    '-s', '[TCP:flags:S]-drop-|[TCP:flags:SEC]-drop-| \/')) -eq 1) "eval: exec probe goes through the engine"
Check ((Fetch) -match '^[23]') "HTTP works after the evaluator is gone"

# A missing driver must be a clear error, not a crash.
$bare = Join-Path $Work "bare"
New-Item -ItemType Directory $bare | Out-Null
Copy-Item $Bin $bare
& (Join-Path $bare "geneva.exe") run -s '\/' -p 80 --duration 1 2>&1 | Out-Null
Check ($LASTEXITCODE -eq 1) "no WinDivert.dll: exit 1 (got $LASTEXITCODE)"

if ($script:Failed) { Write-Host "smoke: $script:Failed failed"; exit 1 }
Write-Host "smoke: all passed"
exit 0 # the last native command failed on purpose: do not report its code
