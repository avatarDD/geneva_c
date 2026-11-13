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
    # one -o per URL: with a single -o, curl prints the later bodies
    $urls = @(); for ($i = 0; $i -lt $times; $i++) { $urls += @("-o", "NUL", "http://$name/") }
    $codes = & curl.exe -s -w "%{http_code} " --max-time $timeout --resolve "${name}:80:$ip" @urls
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
        # the last ACK of A's teardown can leave after curl returns: let it
        # pass before the counters that B must not move are read
        Start-Sleep -Seconds 1
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

# ---- X9c: --ext-auto observe through a WinDivert sniff handle ----
# The engine leaves port 80 alone (empty strategy); the observer sees every
# flow of the PC. Two connections to an address that never answers
# (TEST-NET-1) make its key impaired with BLACKHOLE_SYN.
$EventsA = Join-Path $Work "auto.jsonl"
$LogA = Join-Path $Work "auto.log"
$p = Start-Engine @("--ext", "--ext-auto", "observe", "-s", "\/", "-p", "80", "-c", $Ctl) $EventsA $LogA
try {
    Check (Wait-Event "ready" 20) "--ext-auto: engine is ready"
    Check ((Fetch) -match '^[23]') "--ext-auto: HTTP works"
    & curl.exe -s -o NUL --max-time 10 https://example.com/ | Out-Null
    for ($i = 0; $i -lt 2; $i++) { & curl.exe -s -o NUL --max-time 7 http://192.0.2.1:8443/ | Out-Null }
    Start-Sleep -Seconds 2
    $x = Ctl @("ext_status")
    Check ($x.auto -eq "observe" -and $x.source -eq "windivert" -and $x.observing) "--ext-auto: observing through windivert"
    Check ($x.packets -gt 10 -and $x.flows_ok -ge 2) "--ext-auto: packets $($x.packets), flows ok $($x.flows_ok)"
    Check ($x.counters) "--ext-auto: the detector counts the bytes"
    $imp = Events | Where-Object { $_.ev -eq "ext_impaired" -and $_.key -eq "192.0.2.1" }
    Check ($imp -and $imp.class -in @("BLACKHOLE_SYN", "ICMP_PROHIBIT")) "--ext-auto: 192.0.2.1 impaired ($($imp.class))"
    $bad = Events | Where-Object { $_.ev -eq "ext_impaired" -and $_.impaired -and $_.key -notlike "192.0.2.*" -and $_.key -ne "tcp/8443" }
    Check (!$bad) "--ext-auto: nothing else impaired ($(($bad | ForEach-Object { $_.key }) -join ', '))"
    $r = Ctl @("stop")
    Check ($p.WaitForExit(15000) -and $p.ExitCode -eq 0) "--ext-auto: engine exits with 0"
} finally {
    if (!$p.HasExited) { $p.Kill(); $p.WaitForExit() }
    if ($script:Failed) { Write-Host "---- --ext-auto engine log"; if (Test-Path $LogA) { Get-Content $LogA | Select-Object -Last 80 } }
}
$script:Events = $null

# ---- X13c: --nlm-list, --nlm-filter and --ssid-filter (winws2's) ----
# The strategies run only while the network is there; otherwise every packet
# passes untouched. The runner's own network comes from --nlm-list.
$nl = & $Bin run --ext --nlm-list 2>&1
Check ($LASTEXITCODE -eq 0 -and ($nl -match '^NetID   : ')) "--nlm-list: exit 0, networks listed"
$nlAll = & $Bin run --ext --nlm-list=all 2>&1
Check ($LASTEXITCODE -eq 0 -and @($nlAll -match '^NetID').Count -ge @($nl -match '^NetID').Count) "--nlm-list=all: at least the connected ones"
$netId = ($nl -match '^NetID   : ' | Select-Object -First 1) -replace '^NetID   : ', ''
$netName = (($nl -match '^Name    : ' | Select-Object -First 1) -replace '^Name    : ', '') -replace ' \(connected\).*$', ''
Write-Host "    the runner's network: $netName ($netId)"
$EvN = Join-Path $Work "nlm.jsonl"; $LogN = Join-Path $Work "nlm.log"
function Nlm-Case([string]$name, [string[]]$filter, [bool]$fires) {
    $p = Start-Engine (@("--ext", "-s", "`"$strategy`"", "-p", "80", "-c", $Ctl) + $filter) $EvN $LogN
    try {
        Check (Wait-Event "ready" 20) "${name}: engine is ready"
        Start-Sleep -Milliseconds 500
        Check ((Fetch) -match '^[23]') "${name}: HTTP works"
        Start-Sleep -Milliseconds 1500
        $s = Ctl @("stats")
        if ($fires) { Check ($s.triggered -ge 1) "${name}: the strategy runs ($($s.triggered))" }
        else { Check ($s.triggered -eq 0 -and $s.pkts_out -gt 0) "${name}: packets pass untouched ($($s.pkts_out) out, $($s.triggered) fired)" }
        $r = Ctl @("stop")
        Check ($p.WaitForExit(15000) -and $p.ExitCode -eq 0) "${name}: engine exits with 0"
    } finally {
        if (!$p.HasExited) { $p.Kill(); $p.WaitForExit() }
        if ($script:Failed -and (Test-Path $LogN)) { Write-Host "---- $name log"; Get-Content $LogN | Select-Object -Last 30 }
    }
}
if ($netId) {
    Nlm-Case "--nlm-filter GUID" @("--nlm-filter", $netId) $true
    Nlm-Case "--nlm-filter name" @("--nlm-filter", "`"$netName`"") $true
    Nlm-Case "--nlm-filter of another network" @("--nlm-filter", "no-such-network") $false
    Nlm-Case "--nlm-filter-neg of another network" @("--nlm-filter", "no-such-network", "--nlm-filter-neg") $true
    Nlm-Case "--nlm-filter-neg of this network" @("--nlm-filter", $netId, "--nlm-filter-neg=1") $false
} else {
    Fail "--nlm-list named no connected network"
}
# a server without the WLAN service has no wlanapi.dll: a clear error then
$ws = & $Bin run --ext -s '\/' -p 80 --ssid-filter no-such-ssid --duration 2 2>&1
Write-Host "    --ssid-filter: exit $LASTEXITCODE`: $($ws -join ' | ')"
Check (($LASTEXITCODE -eq 0 -and ($ws -match 'not present')) -or ($LASTEXITCODE -ne 0 -and ($ws -match 'wlanapi'))) "--ssid-filter: absent network or a clear wlanapi error"
$script:Events = $null

# ---- X13d: the sandbox of run --ext (winws2's win_sandbox) ----
# Once packets flow the engine runs at Low integrity with no privilege but
# SeChangeNotifyPrivilege; the files it writes later carry the Low label.
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class GenevaTok {
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr p, uint a, out IntPtr t);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool GetTokenInformation(IntPtr t, int c, IntPtr i, int l, out int r);
    [DllImport("advapi32.dll")] static extern IntPtr GetSidSubAuthority(IntPtr sid, uint n);
    [DllImport("advapi32.dll")] static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    static IntPtr Info(IntPtr proc, int cls, out IntPtr tok) {
        int n;
        tok = IntPtr.Zero;
        if (!OpenProcessToken(proc, 8, out tok)) return IntPtr.Zero;
        GetTokenInformation(tok, cls, IntPtr.Zero, 0, out n);
        IntPtr b = Marshal.AllocHGlobal(n);
        if (GetTokenInformation(tok, cls, b, n, out n)) return b;
        Marshal.FreeHGlobal(b);
        return IntPtr.Zero;
    }
    // TokenIntegrityLevel: the RID of the label (0x1000 Low, 0x2000 Medium, 0x3000 High)
    public static int Integrity(IntPtr proc) {
        IntPtr t, b = Info(proc, 25, out t);
        if (b == IntPtr.Zero) return -1;
        IntPtr sid = Marshal.ReadIntPtr(b);
        int c = Marshal.ReadByte(GetSidSubAuthorityCount(sid));
        int rid = Marshal.ReadInt32(GetSidSubAuthority(sid, (uint)(c - 1)));
        Marshal.FreeHGlobal(b);
        CloseHandle(t);
        return rid;
    }
    // TokenPrivileges: how many are left
    public static int Privileges(IntPtr proc) {
        IntPtr t, b = Info(proc, 3, out t);
        if (b == IntPtr.Zero) return -1;
        int n = Marshal.ReadInt32(b);
        Marshal.FreeHGlobal(b);
        CloseHandle(t);
        return n;
    }
}
"@
$EvS = Join-Path $Work "sandbox.jsonl"; $LogS = Join-Path $Work "sandbox.log"
$State = Join-Path $Work "tune.state"; $Pid1 = Join-Path $Work "geneva.pid"
$p = Start-Engine @("--ext", "--ext-arm", "`"$strategy`"", "--ext-arm", "`"$strategy`"", "--ext-tune", "ts:inseq=64",
    "--ext-state", "`"$State`"", "--pidfile", "`"$Pid1`"", "-p", "80", "-c", $Ctl) $EvS $LogS
try {
    Check (Wait-Event "ready" 20) "sandbox: engine is ready"
    Start-Sleep -Milliseconds 300
    Check (Select-String -Quiet -Path $LogS -Pattern 'sandbox: on: Low integrity') "sandbox: the log says it is on"
    $il = [GenevaTok]::Integrity($p.Handle)
    Check ($il -eq 0x1000) "sandbox: Low integrity (RID 0x$('{0:X}' -f $il))"
    $np = [GenevaTok]::Privileges($p.Handle)
    Check ($np -eq 1) "sandbox: one privilege left ($np)"
    $lab = (& icacls.exe $State) -join ' '
    Check ($lab -match 'Low Mandatory Level') "sandbox: --ext-state has the Low label"
    Check ((& icacls.exe $Pid1) -join ' ' -match 'Low Mandatory Level') "sandbox: --pidfile has the Low label"
    Check ((Fetch) -match '^[23]') "sandbox: HTTP works"
    Check ((Fetch) -match '^[23]') "sandbox: HTTP works again"
    $s = Ctl @("stats")
    Check ($s.triggered -ge 1) "sandbox: the strategy runs ($($s.triggered))"
    # set_filter opens a new WinDivert handle at Low integrity
    $r = Ctl @("set_filter", "filter=tcp")
    Check $r.ok "sandbox: set_filter opens WinDivert again ($($r.error))"
    Check ((Fetch) -match '^[23]') "sandbox: HTTP works after set_filter"
    $r = Ctl @("stop")
    Check ($p.WaitForExit(15000) -and $p.ExitCode -eq 0) "sandbox: engine exits with 0 (got $($p.ExitCode))"
    Check (!(Test-Path $Pid1)) "sandbox: the pidfile is removed"
    Check ((Test-Path $State) -and (Select-String -Quiet -Path $State -Pattern '"key"')) "sandbox: --ext-state written in place"
    Check ((Fetch) -match '^[23]') "sandbox: HTTP works after the engine is gone"
} finally {
    if (!$p.HasExited) { $p.Kill(); $p.WaitForExit() }
    if ($script:Failed -and (Test-Path $LogS)) { Write-Host "---- sandbox log"; Get-Content $LogS | Select-Object -Last 40 }
}
$p = Start-Engine @("--ext", "--ext-sandbox=0", "-s", "`"$strategy`"", "-p", "80", "-c", $Ctl) $EvS $LogS
try {
    Check (Wait-Event "ready" 20) "--ext-sandbox 0: engine is ready"
    Start-Sleep -Milliseconds 300
    $il = [GenevaTok]::Integrity($p.Handle)
    Check ($il -ge 0x3000) "--ext-sandbox 0: integrity stays (RID 0x$('{0:X}' -f $il))"
    $r = Ctl @("stop")
    Check ($p.WaitForExit(15000) -and $p.ExitCode -eq 0) "--ext-sandbox 0: engine exits with 0"
} finally {
    if (!$p.HasExited) { $p.Kill(); $p.WaitForExit() }
}
$script:Events = $null

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
