# 스타세이비어 내 정보 추출 도구 (설치 불필요: Windows 10/11 기본 기능만 사용)
#  - 캡처: Windows 내장 pktmon (게임 서버와의 통신을 "듣기만" 합니다. 게임·통신을 변경하지 않습니다)
#  - 해독: 이 파일에 내장된 코드(Windows PowerShell 의 기본 컴파일러 사용)
# 결과: 내정보.json (닉네임·UID·로그인 정보는 담기지 않습니다). 캡처 파일은 작업 후 자동 삭제됩니다(해독에 실패한 경우만 원인 분석용으로 남깁니다).
param(
    [string]$Out = '',
    [string]$Pcap = '',        # 이미 만든 캡처 파일을 해독만 할 때
    [string]$StopFile = '',    # 자동화용(이 파일이 생기면 캡처 종료)
    [int]$Port = 0,            # 0 = 자동(TCP 전체를 받고 해독기가 서버 흐름을 고름). 서버 포트는 업데이트로 바뀐 적이 있음(9340 -> 9390)
    [string]$Page = 'https://qooreche.github.io/starsavior-party-navigator/',   # 끝나면 이 사이트를 열고 데이터를 넘김
    [switch]$NoOpen
)
$ErrorActionPreference = 'Stop'
$BuildLabel = '26105710'
$auto = [bool]$StopFile

function Say([string]$m, [string]$c = 'White') { Write-Host $m -ForegroundColor $c }
function Pause-End { if (-not $auto) { Write-Host ''; [void](Read-Host '엔터를 누르면 창이 닫힙니다') } }
$diag = New-Object System.Collections.Generic.List[string]
function DiagAdd([string]$m) { [void]$diag.Add($m) }

# CommandLineToArgvW / C runtime quoting: double backslashes before a quote or closing quote.
function Quote-WindowsArg([string]$Value) {
    '"' + [regex]::Replace([regex]::Replace($Value, '(\\*)"', '$1$1\"'), '(\\+)$', '$1$1') + '"'
}
function Validate-Inputs {
    if ($Port -lt 0 -or $Port -gt 65535) { throw '포트는 0~65535여야 합니다.' }
    if (-not $Out) { $script:Out = Join-Path ([Environment]::GetFolderPath('Desktop')) '내정보.json' }
    if ($Out.IndexOfAny([IO.Path]::GetInvalidPathChars()) -ge 0 -or $Out -match '[\x00-\x1f]' -or $Out -match '[\\/]$') { throw '저장 파일 경로가 올바르지 않습니다.' }
    $script:Out = [IO.Path]::GetFullPath($Out)
    if ([IO.Path]::GetFileName($Out).IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0) { throw '저장 파일 이름이 올바르지 않습니다.' }
    if ($Page) {
        $uri = $null
        if ($Page -match '[\x00-\x20"<>\\]' -or -not [Uri]::TryCreate($Page, [UriKind]::Absolute, [ref]$uri) -or $uri.Scheme -notin @('http', 'https') -or $uri.UserInfo -or $uri.Fragment) { throw '사이트 주소는 사용자 정보·해시가 없는 http/https 주소여야 합니다.' }
        $script:Page = $uri.AbsoluteUri
    }
}
function Get-ShortPath([string]$Path) {
    try {
        $fs = New-Object -ComObject Scripting.FileSystemObject
        try { return $fs.GetFolder($Path).ShortPath } finally { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($fs) }
    } catch { return $null }
}
function Normalize-IP([string]$Value) {
    $ip = $null; $v = ($Value.Trim('[', ']') -split '%', 2)[0]
    if ([Net.IPAddress]::TryParse($v, [ref]$ip)) {
        if ($ip.IsIPv4MappedToIPv6) { $ip = $ip.MapToIPv4() }
        return ([BitConverter]::ToString($ip.GetAddressBytes()))
    }
    return $null
}
$script:IpAliases = @{}
function Mask-Diag([string]$t) {
    $roots = @(@($env:TEMP, '%TEMP%'), @([Environment]::GetFolderPath('Desktop'), '%DESKTOP%'), @($env:OneDrive, '%OneDrive%'), @($env:OneDriveCommercial, '%OneDrive%'), @($env:USERPROFILE, '%USERPROFILE%'))
    $paths = @()
    foreach ($pair in $roots) {
        if ($pair[0]) {
            $paths += ,$pair
            $short = Get-ShortPath $pair[0]
            if ($short) { $paths += ,@($short, $pair[1]) }
        }
    }
    foreach ($pair in ($paths | Sort-Object { $_[0].Length } -Descending)) {
        $pat = '(?<![\w\\/])' + ([regex]::Escape($pair[0].TrimEnd('\', '/')) -replace '\\\\', '[\\/]') + '(?=[\\/]|$|[\s"''),;])'
        $replacement = $pair[1]
        $t = [regex]::Replace($t, $pat, [Text.RegularExpressions.MatchEvaluator]{ param($m) $replacement }, 'IgnoreCase')
    }
    # Only complete path components, never a username embedded in arbitrary text.
    $names = @($env:USERNAME, $(if ($env:USERPROFILE) { Split-Path $env:USERPROFILE -Leaf }))
    $shortHome = Get-ShortPath $env:USERPROFILE
    if ($shortHome) { $names += Split-Path $shortHome -Leaf }
    foreach ($name in $names) {
        if ($name) { $t = [regex]::Replace($t, '(?<=[\\/])' + [regex]::Escape($name) + '(?=[\\/]|$|["''])', '%USERNAME%', 'IgnoreCase') }
    }
    $local = @{}
    try {
        foreach ($ni in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            foreach ($ua in $ni.GetIPProperties().UnicastAddresses) { $local[(Normalize-IP $ua.Address.ToString())] = $true }
        }
    } catch { }
    foreach ($addr in @('127.0.0.1', '::1') + @($script:ExtraLocalAddresses)) { if ($addr) { $local[(Normalize-IP $addr)] = $true } }
    # Whole candidates are parsed before replacement, so IPv6 compression/case/scope cannot leak or partially match.
    $pattern = '(?<![\w:.])(?:(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?|[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]+(?:%[\w.-]+)?)(?![\w:.])'
    return [regex]::Replace($t, $pattern, [Text.RegularExpressions.MatchEvaluator]{
        param($m)
        $candidate = $m.Value; $portSuffix = ''
        if ($candidate -match '^(\d+\.\d+\.\d+\.\d+)(:\d+)$') { $candidate = $Matches[1]; $portSuffix = $Matches[2] }
        $key = Normalize-IP $candidate
        if (-not $key) { return $m.Value }
        if ($local.ContainsKey($key)) { return '(내 PC IP)' + $portSuffix }
        if (-not $script:IpAliases.ContainsKey($key)) { $script:IpAliases[$key] = '(상대 IP ' + ($script:IpAliases.Count + 1) + ')' }
        return $script:IpAliases[$key] + $portSuffix
    })
}
function Remove-CaptureFile([string]$Path) {
    if ($Path -and (Test-Path -LiteralPath $Path)) {
        try { Remove-Item -LiteralPath $Path -Force -ErrorAction Stop; DiagAdd ('capture-deleted: ' + $Path) }
        catch {
            DiagAdd ('capture-delete-failed: ' + $Path + ' ' + $_.Exception.GetType().Name)
            Say ('캡처 삭제 실패: ' + $Path + ' (계정 정보가 있으니 보내지 말 것)') 'Yellow'
        }
    }
}
function Clear-ExpiredCaptures([string]$Directory) {
    if (-not (Test-Path -LiteralPath $Directory)) { return }
    try {
        Get-ChildItem -LiteralPath $Directory -File -ErrorAction Stop | Where-Object {
            $_.Name -match '^cap(?:-[0-9a-f-]+)?\.(pcapng|etl)$' -and $_.LastWriteTimeUtc -lt [DateTime]::UtcNow.AddHours(-24)
        } | ForEach-Object { Remove-CaptureFile $_.FullName }
    } catch { DiagAdd ('capture-expiry-failed: ' + $_.Exception.GetType().Name) }
}
function Cleanup-Capture {
    if ($script:CaptureActive) {
        [void](Pkt stop); [void](Pkt filter remove); $script:CaptureActive = $false
    }
    if (-not $Pcap) {
        Remove-CaptureFile $etl
        if (-not $keepCap) { Remove-CaptureFile $pcapPath }
    }
}
function Preserve-Capture {
    if (-not $Pcap -and $pcapPath -and (Test-Path -LiteralPath $pcapPath)) {
        $script:keepCap = $true
        Say ('[참고] 통신 기록 보존: ' + $pcapPath) 'Yellow'
        Say '계정 정보가 있으니 보내지 말 것. 24시간이 지난 뒤 다음 실행 시작 때 삭제합니다.' 'Yellow'
        DiagAdd ('capture-preserved (do not send; expires after 24h at next run): ' + $pcapPath)
    }
}
function Write-Diagnostic([string]$Message, [string]$Desktop = [Environment]::GetFolderPath('Desktop'), [string]$Fallback = $env:TEMP) {
    foreach ($dir in @($Desktop, $Fallback)) {
        try {
            $dp = Join-Path $dir '내정보_진단.txt'
            $hdr = @('스타세이비어 내 정보 추출 진단 (원시 통신·게임 데이터 없음, PC 사용자 경로·주소 가림)', ('build ' + $BuildLabel + ', ' + (Get-Date -Format 's')), ('OS ' + [Environment]::OSVersion.VersionString + ', PS ' + $PSVersionTable.PSVersion), ('오류: ' + $Message), '')
            [IO.File]::WriteAllText($dp, (Mask-Diag (($hdr + $diag.ToArray()) -join "`r`n")), (New-Object Text.UTF8Encoding($true)))
            return $dp
        } catch { DiagAdd ('diagnostic-save-failed: ' + $dir + ' ' + $_.Exception.GetType().Name) }
    }
    return $null
}
function Fail([string]$m) {
    Cleanup-Capture
    Say ('[오류] ' + $m) 'Red'
    $dp = Write-Diagnostic $m
    if ($dp) {
        Say ('진단 파일을 관리자에게 보내 주세요: ' + $dp) 'Yellow'
        if (-not $auto -and -not $NoOpen) { try { Start-Process explorer.exe -ArgumentList ('/select,"{0}"' -f $dp) } catch {} }
    } else { Say '바탕화면과 임시 폴더 모두 진단 저장에 실패했습니다. 저장 권한과 디스크 여유 공간을 확인해 주세요.' 'Yellow' }
    Pause-End; exit 1
}
function Pkt {
    $r = ''; $code = -1
    try {
        $psi = New-Object Diagnostics.ProcessStartInfo 'pktmon'
        $psi.Arguments = (($args | ForEach-Object { Quote-WindowsArg "$_" }) -join ' ')
        $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true
        $latin = [Text.Encoding]::GetEncoding(28591); $psi.StandardOutputEncoding = $latin; $psi.StandardErrorEncoding = $latin
        $pr = [Diagnostics.Process]::Start($psi)
        try {
            $errTask = $pr.StandardError.ReadToEndAsync(); $outText = $pr.StandardOutput.ReadToEnd(); $pr.WaitForExit(); $code = $pr.ExitCode
            $raw = $latin.GetBytes($outText + $errTask.Result)
            try { $r = (New-Object Text.UTF8Encoding($false, $true)).GetString($raw) }
            catch { $r = [Text.Encoding]::GetEncoding([Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage).GetString($raw) }
        } finally { $pr.Dispose() }
    } catch { $r = 'EXC ' + $_.Exception.Message }
    $script:PktExitCode = $code
    DiagAdd ('> pktmon ' + ($args -join ' ') + ' exit=' + $code + "`r`n" + $r.Trim()); return $r.Trim()
}
function Record-GameState([string]$Phase) {
    $procs = @(Get-Process -Name StarSavior -ErrorAction SilentlyContinue)
    DiagAdd ('game ' + $Phase + ' present=' + ($procs.Count -gt 0))
    foreach ($proc in $procs) {
        $script:GameSeen = $true; $script:GamePids[$proc.Id] = $true
        try {
            $started = $proc.StartTime.ToUniversalTime()
            DiagAdd ('game ' + $Phase + ' PID=' + $proc.Id + ' start=' + $started.ToString('o'))
            if ($script:CaptureStart -and $started -lt $script:CaptureStart) { $script:GamePreexisting = $true }
        } catch { DiagAdd ('game start-query-failed PID=' + $proc.Id) }
    }
    if ($Phase -eq 'end') {
        try {
            $connections = @(Get-NetTCPConnection -ErrorAction Stop | Where-Object { $script:GamePids.ContainsKey([int]$_.OwningProcess) })
            DiagAdd ('game TCP count=' + $connections.Count)
            foreach ($c in $connections) {
                $script:GameConnected = $true
                DiagAdd ('game TCP PID=' + $c.OwningProcess + ' local=[' + $c.LocalAddress + ']:' + $c.LocalPort + ' remote=[' + $c.RemoteAddress + ']:' + $c.RemotePort + ' state=' + $c.State)
            }
        } catch { DiagAdd ('game TCP query-failed: ' + $_.Exception.GetType().Name) }
    }
}
function Get-FailureGuidance {
    if ($script:GamePreexisting) { return '게임을 완전히 종료한 뒤 다시 해 주세요' }
    if (-not $Pcap -and -not $script:GameSeen) { return '게임을 켜서 로비까지 들어간 뒤 엔터를 눌러 주세요' }
    return '게임 업데이트로 도구 갱신이 필요할 수 있습니다. 바탕화면 내정보_진단.txt 를 관리자에게 보내 주세요'
}


$work = Join-Path $env:TEMP 'ss_myinfo'
$etl = ''; $pcapPath = $Pcap; $keepCap = $false; $script:CaptureActive = $false
$script:GamePids = @{}; $script:GameSeen = $false; $script:GamePreexisting = $false; $script:GameConnected = $false
Clear-ExpiredCaptures $work
try { Validate-Inputs } catch { Fail $_.Exception.Message }

# ---------- 관리자 권한 (캡처에 필요) ----------
if (-not $Pcap) {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Say '관리자 확인 창이 나오면 [예]를 눌러 주세요. (Windows 내장 통신 확인 도구를 쓰는 데 필요합니다)' 'Yellow'
        $launch = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath, '-Port', "$Port", '-Out', $Out)
        if ($Page) { $launch += @('-Page', $Page) }
        if ($StopFile) { $launch += @('-StopFile', $StopFile) }
        if ($NoOpen -or -not $Page) { $launch += '-NoOpen' }
        $a = ($launch | ForEach-Object { Quote-WindowsArg $_ }) -join ' '
        try { Start-Process powershell -Verb RunAs -ArgumentList $a }
        catch {
            DiagAdd ('elevation-failed: ' + $_.Exception.GetType().Name)
            Fail '관리자 실행이 취소되었거나 시작되지 않았습니다. 다시 실행해 관리자 확인 창에서 [예]를 눌러 주세요.'
        }
        exit
    }
}

# ---------- 해독기 준비 ----------
$src = @'
// 스타세이비어 로그인 응답(LOGIN_ACK) 수동 캡처 해독 -> 내정보.json (ss-myinfo-v1)
// .NET Framework 4.x 만 사용(Windows PowerShell 5.1 의 Add-Type 으로 컴파일: 별도 SDK·런타임 설치 불필요).
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Web.Script.Serialization;

public sealed class EnumV
{
    public long V; public string N;
    public override string ToString() { return N ?? V.ToString(); }
}

public static class SsMyInfo
{
    public const string Format = "ss-myinfo-v1";
    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    struct TraceProperties
    {
        public uint BufferSize, ProviderId; public ulong HistoricalContext; public long TimeStamp;
        public Guid Guid; public uint ClientContext, Flags;
        public uint TraceBufferSize, MinimumBuffers, MaximumBuffers, MaximumFileSize, LogFileMode, FlushTimer, EnableFlags;
        public int AgeLimit; public uint NumberOfBuffers, FreeBuffers, EventsLost, BuffersWritten, LogBuffersLost, RealTimeBuffersLost;
        public IntPtr LoggerThreadId; public uint LogFileNameOffset, LoggerNameOffset;
    }
    [System.Runtime.InteropServices.DllImport("advapi32.dll", CharSet=System.Runtime.InteropServices.CharSet.Unicode)]
    static extern uint QueryAllTracesW([System.Runtime.InteropServices.In, System.Runtime.InteropServices.Out] IntPtr[] properties, uint count, out uint actual);
    public static uint TraceQueryCode;
    public static bool IsCaptureRunning(string path)
    {
        // Verify an active ETW file session for our exact file, independent of localized pktmon text.
        var buffers = new IntPtr[256]; int size = System.Runtime.InteropServices.Marshal.SizeOf(typeof(TraceProperties));
        try
        {
            for (int i=0; i<buffers.Length; i++)
            {
                buffers[i] = System.Runtime.InteropServices.Marshal.AllocHGlobal(size+4096);
                var p = new TraceProperties { BufferSize=(uint)(size+4096), LogFileNameOffset=(uint)size, LoggerNameOffset=(uint)(size+2048) };
                System.Runtime.InteropServices.Marshal.StructureToPtr(p,buffers[i],false);
            }
            uint actual; TraceQueryCode = QueryAllTracesW(buffers,(uint)buffers.Length,out actual);
            if (TraceQueryCode != 0) return false;
            for (int i=0; i<Math.Min(actual,(uint)buffers.Length); i++)
            {
                var p = (TraceProperties)System.Runtime.InteropServices.Marshal.PtrToStructure(buffers[i],typeof(TraceProperties));
                if (p.LogFileNameOffset < size || p.LogFileNameOffset >= size+4096) continue;
                string file = System.Runtime.InteropServices.Marshal.PtrToStringUni(IntPtr.Add(buffers[i],(int)p.LogFileNameOffset));
                if (!String.IsNullOrEmpty(file) && String.Equals(Path.GetFullPath(file),Path.GetFullPath(path),StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }
        finally { foreach (IntPtr b in buffers) if (b != IntPtr.Zero) System.Runtime.InteropServices.Marshal.FreeHGlobal(b); }
    }
    static readonly byte[] StartMagic = { 0xDD, 0xCC, 0xBB, 0xAA };
    static readonly byte[] EndMagic = { 0x44, 0x33, 0x22, 0x11 };
    static readonly ulong[] Masks = { 0xC4A975489AA72956UL, 0xD7C1A29E30FAE47BUL, 0xDCD6D3F2CCC0DEF9UL, 0x3063872F85428EFCUL };

    // ------------------------------------------------------------------ pcapng + TCP
    sealed class Seg { public uint Seq; public byte[] P; }
    sealed class Flow
    {
        public string Key; public int Port, Session; public long Bytes, Packets;
        public bool Syn, Tls, Game; public List<Seg> Segs = new List<Seg>();
    }
    sealed class Connection
    {
        public int Session; public bool Closed, Observed;
        public Dictionary<string, uint> Syns = new Dictionary<string, uint>();
    }
    public static string LastDiag = "";
    static SortedDictionary<string, long> counts = new SortedDictionary<string, long>();
    static void Count(string key) { Count(key, 1); }
    static void Count(string key, long n) { long v; counts.TryGetValue(key, out v); counts[key] = v + n; }
    static uint U32(byte[] d, int p, bool le)
    {
        return le ? (uint)(d[p] | d[p+1] << 8 | d[p+2] << 16 | d[p+3] << 24)
            : (uint)(d[p] << 24 | d[p+1] << 16 | d[p+2] << 8 | d[p+3]);
    }
    static int U16(byte[] d, int p) { return d[p] << 8 | d[p+1]; }
    static string IP(byte[] d, int p, int n)
    {
        byte[] b = new byte[n]; Buffer.BlockCopy(d, p, b, 0, n);
        return new System.Net.IPAddress(b).ToString();
    }

    public static List<byte[]> ServerStreams(string pcapPath, int serverPort)
    {
        LastDiag = ""; counts.Clear();
        byte[] d = File.ReadAllBytes(pcapPath);
        var links = new List<int>(); var snaps = new List<uint>();
        var flows = new Dictionary<string, Flow>(); var connections = new Dictionary<string, Connection>();
        bool le = true; int off = 0, sectionId = 0;
        while (off + 12 <= d.Length)
        {
            bool section = U32(d, off, true) == 0x0A0D0D0A;
            if (section)
            {
                if (U32(d, off+8, true) == 0x1A2B3C4D) le = true;
                else if (U32(d, off+8, false) == 0x1A2B3C4D) le = false;
                else { Count("malformed-block"); break; }
                links.Clear(); snaps.Clear(); connections.Clear(); sectionId++;
            }
            uint type = U32(d, off, le), len = U32(d, off+4, le);
            if (len < 12 || len % 4 != 0 || (long)off + len > d.Length || U32(d, off+(int)len-4, le) != len)
            { Count("malformed-block"); break; }
            Count("block." + type);
            if (type == 1 && len >= 20)
            {
                int lt = le ? d[off+8] | d[off+9] << 8 : U16(d, off+8);
                links.Add(lt); snaps.Add(U32(d, off+12, le)); Count("interface-linktype." + lt);
            }
            else if (type == 6 || type == 3 || type == 2)
            {
                int header = type == 3 ? 12 : 28;
                if (len < header+4) { Count("malformed-packet-block"); off += (int)len; continue; }
                uint iid = type == 3 ? 0 : type == 2 ? (uint)(le ? d[off+8] | d[off+9] << 8 : U16(d, off+8)) : U32(d, off+8, le);
                if (iid >= links.Count) { Count("unknown-interface"); off += (int)len; continue; }
                uint original = U32(d, off+(type == 3 ? 8 : 24), le);
                uint cap = type == 3 ? (snaps[(int)iid] == 0 ? original : Math.Min(original, snaps[(int)iid])) : U32(d, off+20, le);
                if (cap < original) Count("capture-truncated");
                if (cap > len-header-4) { Count("malformed-caplen"); cap = len-(uint)header-4; }
                Count("linktype." + links[(int)iid]);
                ParseTcp(d, off+header, (int)cap, links[(int)iid], sectionId, flows, connections);
            }
            else if (type != 1 && !section) Count("unsupported-block." + type);
            off += (int)len;
        }
        if (off != d.Length) Count("trailing-bytes", d.Length-off);
        var order = new List<Flow>(flows.Values);
        order.Sort((a,b) => { int c = ((a.Port >= 9300 && a.Port <= 9400) ? 0 : 1).CompareTo((b.Port >= 9300 && b.Port <= 9400) ? 0 : 1); return c != 0 ? c : b.Bytes.CompareTo(a.Bytes); });
        var result = new List<byte[]>();
        foreach (Flow f in order)
        {
            // Diagnose all ports, including TLS/443 and flows with no payload.
            List<byte[]> chunks = Assemble(f);
            foreach (byte[] chunk in chunks)
            {
                if (chunk.Length >= 5 && chunk[0] >= 20 && chunk[0] <= 24 && chunk[1] == 3 && chunk[2] <= 4 && U16(chunk, 3) <= 18432) f.Tls = true;
                int at = IndexOf(chunk, StartMagic, 0);
                if (at >= 0 && at+8 <= chunk.Length && U32(chunk, at+4, true) >= 12) f.Game = true;
                if (serverPort <= 0 || f.Port == serverPort) result.Add(chunk);
            }
        }
        var sb = new StringBuilder(); sb.AppendLine("pcapng bytes=" + d.Length);
        foreach (var c in counts) sb.AppendLine(c.Key + "=" + c.Value);
        order.Sort((a,b) => b.Bytes.CompareTo(a.Bytes));
        sb.AppendLine("TCP flows total=" + order.Count + ", listed=" + Math.Min(20, order.Count) + " (top 20, all ports/directions)");
        for (int i=0; i<order.Count && i<20; i++)
        {
            Flow f = order[i]; sb.AppendLine(f.Key + " session=" + f.Session + " bytes=" + f.Bytes + " packets=" + f.Packets + " SYN=" + f.Syn + " TLS=" + f.Tls + " game-header=" + f.Game);
        }
        LastDiag = sb.ToString(); return result;
    }

    static List<byte[]> Assemble(Flow f)
    {
        var output = new List<byte[]>(); if (f.Segs.Count == 0) return output;
        uint anchor = f.Segs[0].Seq;
        f.Segs.Sort((a,b) => unchecked((int)(a.Seq-anchor)).CompareTo(unchecked((int)(b.Seq-anchor))));
        uint first = f.Segs[0].Seq; // Reset after sorting, including sequence wraparound.
        long cur = 0; var ms = new MemoryStream();
        foreach (Seg seg in f.Segs)
        {
            long rel = unchecked((uint)(seg.Seq-first));
            if (rel > cur)
            {
                long gap = rel-cur; Count("gap-count"); Count("gap-bytes", gap);
                if (gap > 1048576) Count("gap-over-limit");
                // Never allocate or decode fabricated bytes across missing data.
                if (ms.Length > 0) output.Add(ms.ToArray()); ms.Dispose(); ms = new MemoryStream(); cur = rel;
            }
            if (rel+seg.P.Length <= cur) { Count("retransmit-packets"); continue; }
            int trim = (int)Math.Max(0, cur-rel);
            if (ms.Length + seg.P.Length-trim > 64*1024*1024)
            { Count("stream-size-limit"); output.Add(ms.ToArray()); ms.Dispose(); ms = new MemoryStream(); }
            ms.Write(seg.P, trim, seg.P.Length-trim); cur = rel+seg.P.Length;
        }
        if (ms.Length > 0) output.Add(ms.ToArray()); ms.Dispose(); return output;
    }

    static void ParseTcp(byte[] d, int pos, int cap, int lt, int sectionId, Dictionary<string, Flow> flows, Dictionary<string, Connection> connections)
    {
        int end = pos+cap, et = 0;
        if (lt == 1) { if (cap < 14) { Count("short-link"); return; } et = U16(d,pos+12); pos += 14; }
        else if (lt == 113) { if (cap < 16) { Count("short-link"); return; } et = U16(d,pos+14); pos += 16; }
        else if (lt == 276) { if (cap < 20) { Count("short-link"); return; } et = U16(d,pos); pos += 20; }
        else if (lt == 0) { if (cap < 4) { Count("short-link"); return; } pos += 4; }
        else if (lt != 101) { Count("unsupported-linktype."+lt); return; }
        if (et != 0)
        {
            Count("EtherType."+et.ToString("X4"));
            while (et == 0x8100 || et == 0x88A8 || et == 0x9100)
            {
                if (end-pos < 4) { Count("short-vlan"); return; }
                et = U16(d,pos+2); pos += 4; Count("EtherType."+et.ToString("X4"));
            }
            if (et != 0x0800 && et != 0x86DD) { Count("non-IP"); return; }
        }
        if (pos >= end) { Count("short-IP"); return; }
        int t, ipEnd, next; string src, dst;
        if ((d[pos] >> 4) == 4)
        {
            if (end-pos < 20) { Count("short-IP"); return; }
            int ihl = (d[pos]&15)*4, total = U16(d,pos+2);
            if (ihl < 20 || total < ihl) { Count("malformed-IP"); return; }
            if (pos+total > end) Count("IP-truncated");
            ipEnd = Math.Min(end,pos+total); next = d[pos+9]; Count("NextHeader."+next);
            if ((U16(d,pos+6)&0x3FFF) != 0) { Count("IPv4-fragment-unsupported"); return; }
            src = IP(d,pos+12,4); dst = IP(d,pos+16,4); t = pos+ihl;
        }
        else if ((d[pos] >> 4) == 6)
        {
            if (end-pos < 40) { Count("short-IP"); return; }
            int plen = U16(d,pos+4); if (plen == 0) { Count("IPv6-jumbo-unsupported"); return; }
            if (pos+40+plen > end) Count("IP-truncated");
            ipEnd = Math.Min(end,pos+40+plen); next = d[pos+6]; t = pos+40;
            src = IP(d,pos+8,16); dst = IP(d,pos+24,16); Count("IPv6");
            Count("NextHeader."+next);
            while (next == 0 || next == 43 || next == 60)
            {
                if (t+2 > ipEnd) { Count("short-extension"); return; }
                int n = (d[t+1]+1)*8;
                if (t+n > ipEnd) { Count("short-extension"); return; }
                next = d[t]; t += n; Count("NextHeader."+next);
            }
            if (next == 44) { Count("IPv6-fragment-unsupported"); return; }
        }
        else { Count("non-IP"); return; }
        if (next != 6) { Count("non-TCP"); return; }
        if (t+20 > ipEnd) { Count("short-TCP"); return; }
        int sport = U16(d,t), dport = U16(d,t+2), th = (d[t+12]>>4)*4;
        if (th < 20 || t+th > ipEnd) { Count("short-TCP"); return; }
        string a = "["+src+"]:"+sport, b = "["+dst+"]:"+dport, direction = a+" > "+b;
        string pair = String.CompareOrdinal(a,b) < 0 ? a+"|"+b : b+"|"+a;
        Connection conn; if (!connections.TryGetValue(pair,out conn)) { conn = new Connection(); connections[pair] = conn; }
        bool syn = (d[t+13]&2) != 0; uint seq = U32(d,t+4,false), old;
        if (syn)
        {
            if (conn.Closed || (conn.Syns.TryGetValue(direction,out old) && old != seq) || (conn.Syns.Count == 0 && conn.Observed))
            { conn.Session++; conn.Syns.Clear(); conn.Closed = false; Count("session-restarts"); }
            conn.Syns[direction] = seq;
        }
        conn.Observed = true;
        string key = sectionId+"#"+direction+"#"+conn.Session;
        Flow f; if (!flows.TryGetValue(key,out f)) { f = new Flow { Key=direction, Port=sport, Session=conn.Session }; flows[key] = f; }
        f.Packets++; f.Syn |= syn;
        int nbytes = ipEnd-t-th; f.Bytes += nbytes;
        if (nbytes > 0)
        {
            byte[] p = new byte[nbytes]; Buffer.BlockCopy(d,t+th,p,0,nbytes);
            f.Segs.Add(new Seg { Seq=unchecked(seq+(syn ? 1U : 0U)), P=p });
        }
        if ((d[t+13]&5) != 0) conn.Closed = true;
    }

    // ------------------------------------------------------------------ 프레임
    sealed class Frame { public int PacketId; public bool Compressed; public byte[] Body; }

    static IEnumerable<Frame> Frames(byte[] s)
    {
        int off = 0;
        while (true)
        {
            int st = IndexOf(s, StartMagic, off);
            if (st < 0 || st + 8 > s.Length) yield break;
            uint fl = BitConverter.ToUInt32(s, st + 4);
            if (fl < 12 || (long)st + fl > s.Length) { off = st + 1; continue; }
            int fend = st + (int)fl;
            if (!Eq(s, fend - 4, EndMagic)) { off = st + 1; continue; }
            Frame f;
            if (!TryFrame(s, st, fend, out f)) { off = st + 1; continue; }
            yield return f;
            off = fend;
        }
    }

    static bool TryFrame(byte[] s, int st, int fend, out Frame f)
    {
        f = null;
        try
        {
            int pos = st + 8;
            VarU(s, ref pos, 64);                       // sequence
            int pid = (int)VarU(s, ref pos, 32);
            if (pos >= fend - 4) return false;
            bool comp = s[pos++] != 0;
            int bl = (int)Zig(VarU(s, ref pos, 32));
            if (bl < 0 || pos + bl > fend - 4) return false;
            var body = new byte[bl];
            Buffer.BlockCopy(s, pos, body, 0, bl);
            f = new Frame { PacketId = pid, Compressed = comp, Body = body };
            return true;
        }
        catch (IndexOutOfRangeException) { return false; }
        catch (InvalidDataException) { return false; }
    }

    static int IndexOf(byte[] s, byte[] m, int from)
    {
        for (int i = from; i + m.Length <= s.Length; i++)
        {
            if (s[i] == m[0] && s[i + 1] == m[1] && s[i + 2] == m[2] && s[i + 3] == m[3]) return i;
        }
        return -1;
    }
    static bool Eq(byte[] s, int at, byte[] m) { for (int i = 0; i < m.Length; i++) if (s[at + i] != m[i]) return false; return true; }

    static ulong VarU(byte[] b, ref int pos, int maxBits)
    {
        ulong v = 0; int shift = 0;
        while (shift < maxBits)
        {
            byte x = b[pos++];
            v |= (ulong)(x & 0x7F) << shift;
            if ((x & 0x80) == 0) return v;
            shift += 7;
        }
        throw new InvalidDataException("varint");
    }
    static long Zig(ulong v) { return (long)(v >> 1) ^ -(long)(v & 1); }

    static byte[] XorBody(byte[] data)
    {
        var o = (byte[])data.Clone();
        int off = 0, mi = 0;
        while (off < o.Length)
        {
            ulong m = Masks[mi];
            int rem = o.Length - off;
            if (rem >= 8) { for (int j = 0; j < 8; j++) o[off + j] ^= (byte)(m >> (8 * j)); off += 8; }
            else { byte low = (byte)(m & 0xFF); for (int i = off; i < o.Length; i++) o[i] ^= low; off = o.Length; }
            mi = (mi + 1) % 4;
        }
        return o;
    }

    // ------------------------------------------------------------------ LZ4 (frame)
    static byte[] Lz4Frame(byte[] b)
    {
        if (b.Length < 7 || BitConverter.ToUInt32(b, 0) != 0x184D2204u) throw new InvalidDataException("LZ4 magic");
        int pos = 4; byte flg = b[pos++]; pos++; // BD
        bool blockChk = (flg & 0x10) != 0, hasSize = (flg & 0x08) != 0, hasDict = (flg & 1) != 0;
        if (hasSize) pos += 8; if (hasDict) pos += 4; pos++; // HC
        byte[] o = new byte[Math.Max(1 << 16, b.Length * 3)]; int op = 0;
        while (true)
        {
            uint bs = BitConverter.ToUInt32(b, pos); pos += 4;
            if (bs == 0) break;
            bool raw = (bs & 0x80000000u) != 0; int sz = (int)(bs & 0x7FFFFFFF);
            if (raw) { Ensure(ref o, op + sz); Buffer.BlockCopy(b, pos, o, op, sz); op += sz; }
            else Lz4Block(b, pos, sz, ref o, ref op);
            pos += sz; if (blockChk) pos += 4;
        }
        var r = new byte[op]; Buffer.BlockCopy(o, 0, r, 0, op); return r;
    }

    static void Ensure(ref byte[] o, int need)
    {
        if (need <= o.Length) return;
        int n = o.Length; while (n < need) n *= 2;
        Array.Resize(ref o, n);
    }

    static void Lz4Block(byte[] src, int ip, int len, ref byte[] o, ref int op)
    {
        int end = ip + len;
        while (ip < end)
        {
            int token = src[ip++];
            int lit = token >> 4;
            if (lit == 15) { int s; do { s = src[ip++]; lit += s; } while (s == 255); }
            Ensure(ref o, op + lit);
            Buffer.BlockCopy(src, ip, o, op, lit); ip += lit; op += lit;
            if (ip >= end) break;
            int offset = src[ip] | (src[ip + 1] << 8); ip += 2;
            int ml = token & 15;
            if (ml == 15) { int s; do { s = src[ip++]; ml += s; } while (s == 255); }
            ml += 4;
            Ensure(ref o, op + ml);
            int from = op - offset;
            if (from < 0) throw new InvalidDataException("LZ4 offset");
            for (int i = 0; i < ml; i++) o[op + i] = o[from + i];
            op += ml;
        }
    }

    // ------------------------------------------------------------------ 스키마 해독
    sealed class Rd
    {
        public byte[] B; public int P;
        public byte Byte() { return B[P++]; }
        public bool Bool() { return B[P++] != 0; }
        public ulong VU(int bits) { return VarU(B, ref P, bits); }
        public long I32() { return (int)Zig(VU(32)); }
        public long I64() { return Zig(VU(64)); }
        public int U16() { return (int)(VU(32) & 0xFFFF); }
        public int Short() { return (short)Zig(VU(32)); }
        public string Str()
        {
            int n = Short();
            if (n == -1) return null;
            if (n < 0) throw new InvalidDataException("string len");
            string s = Encoding.UTF8.GetString(B, P, n); P += n; return s;
        }
        public long Raw8() { long v = BitConverter.ToInt64(B, P); P += 8; return v; }
    }

    sealed class Schema
    {
        public Dictionary<string, object> Classes, Enums;
        public string PacketClass;
    }

    static Schema LoadSchema(string json)
    {
        var js = new JavaScriptSerializer(); js.MaxJsonLength = int.MaxValue; js.RecursionLimit = 200;
        var root = (Dictionary<string, object>)js.DeserializeObject(json);
        var pk = (Dictionary<string, object>)((Dictionary<string, object>)root["packet_ids"])["403"];
        return new Schema { Classes = (Dictionary<string, object>)root["classes"], Enums = (Dictionary<string, object>)root["enums"], PacketClass = (string)pk["class"] };
    }

    static List<string> DiagPath = new List<string>();
    // LOGIN_ACK(403) 프레임을 찾았으나 해독에 실패했는지(템플릿이 캡처 파일을 보존할지 판단)
    public static bool LoginAckFailed = false;

    static string PathSummary()
    {
        var sb = new StringBuilder();
        for (int i = 0; i < DiagPath.Count; i++) { if (i > 0) sb.Append(" > "); sb.Append(DiagPath[i]); }
        return sb.ToString();
    }

    static object DecodeClass(Rd r, Schema sc, string cn)
    {
        object o;
        if (!sc.Classes.TryGetValue(cn, out o)) throw new InvalidDataException("class not found: " + cn);
        var desc = (Dictionary<string, object>)o;
        var fields = (Dictionary<string, object>)desc["fields"];
        var order = (object[])desc["order"];
        var vals = new List<object>(order.Length);
        int fi = 0;
        foreach (object po in order)
        {
            var pair = (object[])po;
            string fn = (string)pair[0], kind = (string)pair[1];
            fi++;
            // 진단용 경로(클래스 순번 아님: 스키마상 이름, 필드 번호, 형식, 버퍼 위치). 예외가 나면 pop 하지 않아 가장 깊은 위치가 남는다.
            DiagPath.Add(cn + " #" + fi + " (" + (string)fields[fn] + ") @" + r.P + "/" + r.B.Length);
            vals.Add(DecodeValue(r, sc, (string)fields[fn], kind));
            DiagPath.RemoveAt(DiagPath.Count - 1);
        }
        return vals;
    }

    static object DecodeMessage(Rd r, Schema sc, string cn) { return r.Bool() ? DecodeClass(r, sc, cn) : null; }

    static EnumV MakeEnum(Schema sc, string type, long v)
    {
        string name = null; object eo;
        foreach (string key in new[] { type, type.Substring(type.LastIndexOf('.') + 1) })
        {
            if (sc.Enums.TryGetValue(key, out eo)) { var m = eo as Dictionary<string, object>; object n; if (m != null && m.TryGetValue(v.ToString(), out n)) { name = (string)n; break; } }
        }
        return new EnumV { V = v, N = name };
    }

    static bool Prim(Rd r, string t, out object val)
    {
        switch (t)
        {
            case "bool": val = r.Bool(); return true;
            case "sbyte": val = (long)(sbyte)r.Byte(); return true;
            case "byte": val = (long)r.Byte(); return true;
            case "short": val = (long)r.Short(); return true;
            case "ushort": val = (long)r.U16(); return true;
            case "int": val = r.I32(); return true;
            case "long": val = r.I64(); return true;
            case "float": { float f = BitConverter.ToSingle(r.B, r.P); r.P += 4; val = (double)f; return true; }
            case "double": { double f = BitConverter.ToDouble(r.B, r.P); r.P += 8; val = f; return true; }
            case "string": val = r.Str(); return true;
            case "DateTime": case "TimeSpan": val = r.Raw8(); return true;
        }
        val = null; return false;
    }

    static object DecodeValue(Rd r, Schema sc, string type, string kind)
    {
        type = type.Trim();
        object v;
        if (kind == "enum")
        {
            if (type.StartsWith("List<"))
            {
                string inner = type.Substring(5, type.Length - 6).Trim();
                int n = r.U16(); var l = new List<object>(n);
                for (int i = 0; i < n; i++) l.Add(MakeEnum(sc, inner, r.I32()));
                return l;
            }
            return MakeEnum(sc, type, r.I32());
        }
        if (Prim(r, type, out v)) return v;
        if (type == "byte[]") { int n = (int)r.I32(); var b = new byte[n]; Buffer.BlockCopy(r.B, r.P, b, 0, n); r.P += n; return b; }
        if (type == "int[]") { int n = r.U16(); var l = new List<object>(n); for (int i = 0; i < n; i++) l.Add(r.I32()); return l; }
        if (type.EndsWith("[]")) { string inner = type.Substring(0, type.Length - 2); int n = r.U16(); var l = new List<object>(n); for (int i = 0; i < n; i++) l.Add(DecodeMessage(r, sc, inner)); return l; }
        if (type.StartsWith("Dictionary<"))
        {
            string body = type.Substring(11, type.Length - 12);
            int comma = body.IndexOf(','); string kt = body.Substring(0, comma).Trim(), vt = body.Substring(comma + 1).Trim();
            int n = r.U16(); var d = new Dictionary<string, object>();
            for (int i = 0; i < n; i++)
            {
                object k = DecodeValue(r, sc, kt, "value");
                object val = DecodeValue(r, sc, vt, "value");
                d[Convert.ToString(k)] = val;
            }
            return d;
        }
        if (type.StartsWith("List<") || type.StartsWith("HashSet<"))
        {
            string inner = type.Substring(type.IndexOf('<') + 1, type.Length - type.IndexOf('<') - 2).Trim();
            int n = r.U16(); var l = new List<object>(n);
            object pv;
            for (int i = 0; i < n; i++)
            {
                if (Prim(r, inner, out pv)) l.Add(pv); else l.Add(DecodeMessage(r, sc, inner));
            }
            return l;
        }
        return DecodeMessage(r, sc, type);
    }

    // ------------------------------------------------------------------ 해독 진입점
    public static object DecodeLoginAck(string pcapPath, string schemaJson, int serverPort, out string info)
    {
        var sc = LoadSchema(schemaJson);
        int streams = 0, frames = 0, seen403 = 0, failed = 0;
        LoginAckFailed = false;
        foreach (byte[] s in ServerStreams(pcapPath, serverPort))
        {
            streams++;
            foreach (Frame f in Frames(s))
            {
                frames++;
                if (f.PacketId != 403) continue;
                seen403++;
                DiagPath.Clear();
                string stage = "본문 풀기";
                int bodyLen = f.Body == null ? -1 : f.Body.Length;
                try
                {
                    byte[] body = f.Compressed ? Lz4Frame(f.Body) : XorBody(f.Body);
                    stage = "필드 해독";
                    var r = new Rd { B = body, P = 0 };
                    object obj = DecodeClass(r, sc, sc.PacketClass);
                    if (r.P != body.Length)
                    {
                        failed++;
                        LastDiag += "decode-fail: 403 frame " + frames + " 해독 불일치 끝 위치 " + r.P + "/" + body.Length + Environment.NewLine;
                        continue;
                    }
                    LastDiag += "decode: LOGIN_ACK found in stream " + streams + " (frame " + frames + ")" + Environment.NewLine;
                    info = "stream " + streams + ", frames " + frames + ", body " + body.Length + " bytes";
                    LoginAckFailed = false;
                    return obj;
                }
                catch (Exception ex)
                {
                    failed++;
                    // 내용(값)은 넣지 않는다: 예외 종류, 단계, 프레임 번호, 클래스·필드 경로, 버퍼 위치만.
                    LastDiag += "decode-fail: 403 frame " + frames + " (압축 " + f.Compressed + ", 원본 " + bodyLen + "B) 단계=" + stage + " " + ex.GetType().Name + " @ " + (DiagPath.Count > 0 ? PathSummary() : "(필드 이전)") + Environment.NewLine;
                }
            }
        }
        if (seen403 > 0) LoginAckFailed = true;
        info = "streams " + streams + ", frames " + frames + (seen403 > 0 ? ", LOGIN_ACK " + seen403 + "개 중 해독 실패 " + failed : "");
        LastDiag += "decode: streams " + streams + ", frames " + frames + (seen403 > 0 ? ", LOGIN_ACK(403) " + seen403 + " found, all failed" : ", LOGIN_ACK(403) not found") + Environment.NewLine;
        return null;
    }

    // ------------------------------------------------------------------ 내보내기 (순번 기반: FIELDS.md)
    static long L(object o) { return o == null ? 0 : Convert.ToInt64(o); }
    static List<object> A(object o) { return (List<object>)o; }

    static Dictionary<string, object> Stat(object o)
    {
        var l = A(o); var d = new Dictionary<string, object>();
        d["stat"] = ((EnumV)l[0]).ToString(); d["value"] = L(l[1]); return d;
    }

    public static string Export(object ack, string buildLabel)
    {
        var ud = A(A(ack)[2]);
        var unitsD = (Dictionary<string, object>)ud[1];
        var gauntlets = A(ud[2]);
        var equipsD = (Dictionary<string, object>)ud[14];
        var synchro = A(ud[19]);
        var tactics = A(ud[21]);

        var gByUid = new Dictionary<long, Dictionary<string, object>>();
        foreach (object go in gauntlets)
        {
            var g = A(go); var jd = new Dictionary<string, object>();
            jd["journey"] = A(A(g[6])[0]); jd["level"] = L(g[3]);
            var pots = new List<object>();
            foreach (object po in A(g[8])) { var pl = new List<object>(); foreach (object v in A(po)) pl.Add(L(v)); pots.Add(pl); }
            jd["potentials"] = pots;                                  // [잠재력 ID, ?, ?, ?] (의미 일부 미확정)
            var bl = new List<object>(); foreach (object v in A(g[13])) bl.Add(L(v));
            jd["blessings"] = bl;                                     // 축복 ID 목록
            gByUid[L(g[0])] = jd;
        }

        var units = new List<object>();
        var keys = new List<long>();
        foreach (string k in unitsD.Keys) keys.Add(long.Parse(k));
        keys.Sort();
        foreach (long uid in keys)
        {
            var rec = A(unitsD[uid.ToString()]);
            var equip = new List<object>();
            foreach (object eu in A(rec[8]))
            {
                if (L(eu) == 0) continue;
                object eo;
                if (!equipsD.TryGetValue(L(eu).ToString(), out eo)) continue;
                var e = A(eo); var ed = new Dictionary<string, object>();
                ed["item_id"] = L(e[1]); ed["enhance"] = L(e[2]);
                ed["main"] = Stat(e[5]);
                var subs = new List<object>(); foreach (object so in A(e[6])) subs.Add(Stat(so));
                ed["subs"] = subs; equip.Add(ed);
            }
            var sk = A(rec[5]);
            var skills = new Dictionary<string, object>();
            skills["basic"] = L(sk[1]); skills["special"] = L(sk[2]); skills["ultimate"] = L(sk[3]); skills["passive"] = L(sk[4]);
            var u = new Dictionary<string, object>();
            u["id"] = uid; u["star"] = L(rec[2]); u["sigil"] = L(rec[3]); u["resonance"] = L(rec[4]);
            u["skills"] = skills; u["favor"] = L(rec[10]); u["equip"] = equip;
            Dictionary<string, object> gd;
            if (gByUid.TryGetValue(L(rec[6]), out gd)) u["gauntlet"] = gd;
            units.Add(u);
        }

        var groups = new Dictionary<string, object>();
        foreach (object go in A(tactics[2]))
        {
            var g = A(go); var gd = new Dictionary<string, object>();
            gd["level"] = L(g[1]); gd["attack"] = L(g[2]); gd["defense"] = L(g[3]); gd["hp"] = L(g[4]);
            groups[((EnumV)g[0]).ToString()] = gd;
        }
        var tac = new Dictionary<string, object>();
        tac["facility_level"] = L(tactics[0]); tac["common_level"] = L(tactics[1]); tac["groups"] = groups;

        var root = new Dictionary<string, object>();
        root["format"] = Format; root["game_build"] = buildLabel;
        root["exported_at"] = DateTime.Now.ToString("yyyy-MM-ddTHH:mm:sszzz");
        root["star_link_level"] = L(synchro[2]); root["tactics"] = tac; root["units"] = units;
        // 보유 브레이크 스킬(궤도 배열) ud[31]: [스킬 ID, 레벨]. 스킬 획득·레벨업 응답이 돌려주는 쌍과 같은 클래스(레벨 1~10). 실캡처 대조는 미검증
        var brk = new List<object>();
        foreach (object bo in A(ud[31]))
        {
            var b = A(bo); var bd = new Dictionary<string, object>();
            bd["id"] = L(b[0]); bd["level"] = L(b[1]); brk.Add(bd);
        }
        root["break_skills"] = brk;
        var js = new JavaScriptSerializer(); js.MaxJsonLength = int.MaxValue; js.RecursionLimit = 200;
        return js.Serialize(root);
    }

    // PowerShell 에서 한 번에 호출
    public static string Run(string pcapPath, string schemaJson, string buildLabel, int serverPort, out int unitCount, out string info)
    {
        unitCount = 0;
        object ack = DecodeLoginAck(pcapPath, schemaJson, serverPort, out info);
        if (ack == null) return null;
        string json;
        try { json = Export(ack, buildLabel); }
        catch (Exception ex) { LoginAckFailed = true; LastDiag += "export-fail: " + ex.GetType().Name + " " + ex.Message + Environment.NewLine; throw; }
        var ud = A(A(ack)[2]); unitCount = ((Dictionary<string, object>)ud[1]).Count;
        return json;
    }
}

'@
$schemaB64 = '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'
try {
    Add-Type -TypeDefinition $src -Language CSharp -ReferencedAssemblies 'System.Web.Extensions'
} catch { Fail ('도구를 준비하지 못했습니다: ' + $_.Exception.Message) }
try {
$ms = New-Object IO.MemoryStream (, [Convert]::FromBase64String($schemaB64))
$gz = New-Object IO.Compression.GZipStream ($ms, [IO.Compression.CompressionMode]::Decompress)
$sr = New-Object IO.StreamReader ($gz, [Text.Encoding]::UTF8)
$schemaJson = $sr.ReadToEnd(); $sr.Close()

} catch { Fail '내장 해독 자료를 읽지 못했습니다. 도구를 다시 받아 주세요.' }

try {
    if (-not $Pcap) {
        if (-not (Get-Command pktmon -ErrorAction SilentlyContinue)) { Fail 'Windows 10(1809 이상) 또는 11에서만 쓸 수 있습니다.' }
        New-Item -ItemType Directory -Force $work | Out-Null
        $captureId = [Guid]::NewGuid().ToString()
        $etl = Join-Path $work ('cap-' + $captureId + '.etl')
        $pcapPath = Join-Path $work ('cap-' + $captureId + '.pcapng')

        Say '=============================================================' 'Cyan'
        Say '  스타세이비어 내 정보 추출' 'Cyan'
        Say '=============================================================' 'Cyan'
        # 서버 포트가 업데이트로 바뀐 적이 있다(9340 -> 9390). pktmon 의 -p 는 "포트 둘 다 가진 패킷"만 맞추고 필터는 최대 32개라
        # 포트 구간을 지정할 수 없다. 그래서 -Port 를 주지 않으면 TCP 전체를 받고, 해독기가 9300~9400 흐름을 우선해 고른다.
        [void](Pkt stop); [void](Pkt filter remove)
        if ($Port -gt 0) { [void](Pkt filter add SSGame -t TCP -p $Port) }
        else { [void](Pkt filter add SSGame -t TCP) }
        if ($script:PktExitCode -ne 0) { Fail '캡처 필터 설정에 실패했습니다. 진단 파일의 pktmon 오류를 확인해 주세요.' }
        [void](Pkt filter list)
        [void](Pkt list)
        $script:CaptureStart = [DateTime]::UtcNow
        DiagAdd ('capture-request=' + $script:CaptureStart.ToString('o'))
        Record-GameState 'start'
        if ($script:GamePreexisting) { Say '게임을 완전히 종료한 뒤 다시 해 주세요' 'Yellow' }
        $startOut = Pkt start --capture --pkt-size 0 --file-name $etl
        $startCode = $script:PktExitCode
        $script:CaptureActive = ($startCode -eq 0)
        $script:CaptureStart = [DateTime]::UtcNow
        DiagAdd ('capture-start=' + $script:CaptureStart.ToString('o'))
        Record-GameState 'confirmed'
        [void](Pkt status)
        $traceActive = [SsMyInfo]::IsCaptureRunning($etl)
        DiagAdd ('capture-status ETW=' + $traceActive + ' query-code=' + [SsMyInfo]::TraceQueryCode)
        if (-not $traceActive -and $startCode -eq 0) { DiagAdd 'capture-status: ETW 세션 확인 실패 — 종료 코드 0 이라 계속 진행(확인 방식 오판으로 전원이 막히지 않게)' }
        if ($startCode -ne 0) {
            $reason = '활성 기록을 확인하지 못했습니다. 진단 파일을 관리자에게 보내 주세요.'
            if ($startCode -eq 5) { $reason = '권한이 거부되었습니다. 관리자 권한으로 다시 실행해 주세요.' }
            elseif ($startCode -ne 0) {
                $reason = ($startOut -split '[\r\n]+' | Where-Object { $_.Trim() } | Select-Object -First 1)
                if (-not $reason) { $reason = 'pktmon을 시작하지 못했습니다. 진단 파일을 관리자에게 보내 주세요.' }
                if ($reason.Length -gt 160) { $reason = $reason.Substring(0, 160) }
            }
            Fail ('캡처 시작 실패(종료 코드 ' + $startCode + '): ' + $reason)
        }
        Say ''
        Say '준비됐습니다. 아래 순서대로 해 주세요.' 'Green'
        Say '  1) 스타세이비어를 실행하세요. (켜져 있으면 완전히 종료한 뒤 다시 실행)'
        Say '  2) 로그인해서 로비가 뜨면, 이 창으로 돌아와 엔터를 누르세요.'
        Say ''
        if ($auto) {
            $t0 = Get-Date
            while (-not (Test-Path $StopFile) -and ((Get-Date) - $t0).TotalMinutes -lt 15) { Start-Sleep -Milliseconds 500 }
        } else { [void](Read-Host '로비가 뜨면 엔터를 누르세요') }
        Start-Sleep -Seconds 2   # 마지막 패킷이 캡처에 반영될 시간
        Say '마무리하는 중...'
        Record-GameState 'end'
        DiagAdd ('capture-end=' + [DateTime]::UtcNow.ToString('o'))
        [void](Pkt stop)
        if ($script:PktExitCode -ne 0) { Fail '캡처 종료에 실패했습니다. 진단 파일의 pktmon 오류를 확인해 주세요.' }
        $script:CaptureActive = $false
        DiagAdd ('cap.etl: ' + $(if (Test-Path $etl) { (Get-Item $etl).Length.ToString() + ' bytes' } else { '없음' }))
        [void](Pkt etl2pcap $etl --out $pcapPath)
        $convertCode = $script:PktExitCode
        [void](Pkt filter remove)
        DiagAdd ('cap.pcapng: ' + $(if (Test-Path $pcapPath) { (Get-Item $pcapPath).Length.ToString() + ' bytes' } else { '없음' }))
        if ($convertCode -ne 0 -or -not (Test-Path $pcapPath)) { Fail '통신 기록을 만들지 못했습니다. 관리자 확인 창에서 [예]를 눌렀는지 확인하고 다시 해 보세요.' }
    }

    Say '내 정보를 읽는 중... (몇 초 걸립니다)'
    $units = 0; $info = ''
    $json = [SsMyInfo]::Run($pcapPath, $schemaJson, $BuildLabel, $Port, [ref]$units, [ref]$info)
    DiagAdd ([SsMyInfo]::LastDiag)
    if (-not $json) {
        Preserve-Capture
        DiagAdd ('decode-result: ' + $info)
        Fail (Get-FailureGuidance)
    }
    Cleanup-Capture
    if (($diag -join "`n") -match 'capture-(delete|expiry)-failed:') {
        $cleanupDiag = Write-Diagnostic '캡처 파일 정리에 실패했습니다.'
        Say ('캡처 파일 정리에 실패했습니다. 진단 위치: ' + $cleanupDiag) 'Yellow'
    }
    [IO.File]::WriteAllText($Out, $json, (New-Object Text.UTF8Encoding($false)))
    Say ''
    Say '=============================================================' 'Green'
    Say ('  완료: 구원자 {0}명의 정보를 저장했습니다.' -f $units) 'Green'
    Say ('  저장 위치: ' + $Out) 'Green'
    Say '=============================================================' 'Green'
    if (-not $Pcap) { Say '(통신 기록 파일에는 로그인 정보가 있어 삭제를 시도했습니다. 정리 실패 시 위 진단 위치를 확인해 주세요.)' }
    if (-not $NoOpen -and $Page -and -not $auto) {
        # 주소의 '#' 뒤(해시)에 데이터를 실어 사이트를 연다. 해시는 서버로 전송되지 않고 브라우저 안에서만 읽힌다.
        $bytes = [Text.Encoding]::UTF8.GetBytes($json)
        $m2 = New-Object IO.MemoryStream
        $g2 = New-Object IO.Compression.GZipStream ($m2, [IO.Compression.CompressionMode]::Compress)
        $g2.Write($bytes, 0, $bytes.Length); $g2.Close()
        $b64 = [Convert]::ToBase64String($m2.ToArray()).Replace('+', '-').Replace('/', '_').TrimEnd('=')
        $url = $Page + '#myinfo=' + $b64
        if ($url.Length -lt 30000) {
            Say ''
            Say '사이트를 여는 중... 내 구원자가 자동으로 채워집니다.' 'Cyan'
            # 긴 주소를 explorer 에 직접 주면 해석하지 못하고 폴더가 열린다. 그래서 주소로 이동하는 작은 HTML 을 만들어
            # explorer 로 연다(관리자 창에서도 일반 권한의 기본 브라우저로 열림). 파일은 잠시 뒤 지운다.
            $open = Join-Path $env:TEMP 'ss_myinfo_open.html'
            $safeUrl = $url.Replace('&', '\u0026').Replace('<', '\u003c').Replace('>', '\u003e').Replace("'", '\u0027')
            $h = '<!doctype html><meta charset="utf-8"><title>스타세이비어 내 정보</title><body style="font-family:sans-serif;padding:24px">사이트로 이동 중입니다... 이동하지 않으면 <a id="a">여기</a>를 누르세요.<script>var u="' + $safeUrl + '";document.getElementById("a").href=u;location.replace(u);</script></body>'
            [IO.File]::WriteAllText($open, $h, (New-Object Text.UTF8Encoding($false)))
            Start-Process explorer.exe -ArgumentList ('"{0}"' -f $open)
            Start-Process powershell -WindowStyle Hidden -ArgumentList ('-NoProfile -Command "Start-Sleep 120; Remove-Item -LiteralPath ''{0}'' -Force -ErrorAction SilentlyContinue"' -f $open)
            Say '안 열리면 사이트의 [내 구원자 → 내 정보 불러오기]에서 내정보.json 을 선택하세요.'
        } else {
            Say '자동으로 열기에는 데이터가 큽니다. 사이트의 [내 정보 불러오기]에서 내정보.json 을 선택하세요.' 'Yellow'
        }
    } else {
        Say '파티 네비게이터의 [내 정보 불러오기]에서 이 파일을 선택하세요.'
    }
}
catch {
    DiagAdd ('exception: ' + $_.Exception.GetType().Name + ' ' + $_.Exception.Message)
    DiagAdd ([SsMyInfo]::LastDiag)
    Preserve-Capture
    Fail $_.Exception.Message
}
finally { Cleanup-Capture }
Pause-End
