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
$BuildLabel = '26610546'
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
        Say ('진단 파일 내용을 아카라이브 원글 댓글로 남겨 주세요: ' + $dp) 'Yellow'
        Say '원글: https://arca.live/b/starsavior/186845178' 'Yellow'
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
    if ($Phase -eq 'end') { $script:GamePreexisting = $false }   # 안내대로 재실행했으면 마지막 관측 기준으로 다시 판정
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
    return '게임 업데이트로 도구 갱신이 필요할 수 있습니다. 바탕화면 내정보_진단.txt 내용을 아카라이브 원글 댓글로 남겨 주세요'
}


$work = Join-Path $env:TEMP 'ss_myinfo'
$etl = ''; $pcapPath = $Pcap; $keepCap = $false; $script:CaptureActive = $false
$script:GamePids = @{}; $script:GameSeen = $false; $script:GamePreexisting = $false; $script:GameConnected = $false
if (-not $Pcap) { Clear-ExpiredCaptures $work }   # -Pcap 재분석 때 입력 파일을 지우지 않게
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

    static bool LooksRawIp(byte[] d, int pos, int cap)
    {
        if (cap >= 20 && (d[pos] >> 4) == 4)
        {
            int ihl = (d[pos]&15)*4, total = U16(d,pos+2);
            if (ihl < 20 || ihl > cap || total < ihl || total > cap) return false;
            uint sum = 0;
            for (int i = 0; i < ihl; i += 2) sum += (uint)U16(d,pos+i);
            while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
            return sum == 0xFFFF;
        }
        if (cap >= 40 && (d[pos] >> 4) == 6) return 40+U16(d,pos+4) == cap;
        return false;
    }

    static void ParseTcp(byte[] d, int pos, int cap, int lt, int sectionId, Dictionary<string, Flow> flows, Dictionary<string, Connection> connections)
    {
        int end = pos+cap, et = 0;
        if (lt == 1)
        {
            if (cap < 14) { Count("short-link"); return; }
            int et0 = U16(d,pos+12);
            // VPN 터널 어댑터(예: Cato)는 이더넷 헤더 없이 IP 패킷을 내보내는데 pktmon 이 linktype 1 로 적는다.
            // 종류값이 IP·VLAN 이 아니고 맨 앞이 온전한 IP 헤더(IPv4 체크섬·길이, IPv6 길이 일치)면 그대로 IP 로 읽는다.
            if (et0 != 0x0800 && et0 != 0x86DD && et0 != 0x8100 && et0 != 0x88A8 && et0 != 0x9100 && LooksRawIp(d,pos,cap)) { Count("raw-IP-in-ethernet"); }
            else { et = et0; pos += 14; }
        }
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
            u["id"] = uid; u["level"] = L(rec[1]); u["star"] = L(rec[2]); u["sigil"] = L(rec[3]); u["resonance"] = L(rec[4]);
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
        var link = new Dictionary<string, object>();
        link["level"] = L(synchro[2]);
        var source = new List<object>();
        foreach (object id in A(synchro[3])) source.Add(L(id));
        link["source"] = source;
        var slots = new List<object>();
        foreach (object entry in A(synchro[4]))
        {
            if (entry == null) continue;
            var slot = A(entry); var sd = new Dictionary<string, object>();
            sd["index"] = L(slot[0]); sd["id"] = L(slot[1]); slots.Add(sd);
            // slot[2] is DateTime; it is not a level or an ID.
        }
        link["slots"] = slots; root["star_link"] = link;
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
        $traceActive = $false
        try { $traceActive = [SsMyInfo]::IsCaptureRunning($etl) } catch { DiagAdd ('capture-status query-exception: ' + $_.Exception.GetType().Name) }
        DiagAdd ('capture-status ETW=' + $traceActive + ' query-code=' + [SsMyInfo]::TraceQueryCode)
        if (-not $traceActive -and $startCode -eq 0) { DiagAdd 'capture-status: ETW 세션 확인 실패 — 종료 코드 0 이라 계속 진행(확인 방식 오판으로 전원이 막히지 않게)' }
        if ($startCode -ne 0) {
            $reason = '활성 기록을 확인하지 못했습니다. 진단 파일 내용을 아카라이브 원글 댓글로 남겨 주세요.'
            if ($startCode -eq 5) { $reason = '권한이 거부되었습니다. 관리자 권한으로 다시 실행해 주세요.' }
            elseif ($startCode -ne 0) {
                $reason = ($startOut -split '[\r\n]+' | Where-Object { $_.Trim() } | Select-Object -First 1)
                if (-not $reason) { $reason = 'pktmon을 시작하지 못했습니다. 진단 파일 내용을 아카라이브 원글 댓글로 남겨 주세요.' }
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
        if ($convertCode -ne 0 -or -not (Test-Path $pcapPath)) { Fail ('통신 기록 변환에 실패했습니다(종료 코드 ' + $convertCode + '). 디스크 공간을 확인하고 다시 해 보세요. 계속되면 진단 파일 내용을 아카라이브 원글 댓글로 남겨 주세요.') }
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
            Say '안 열리면 사이트의 [내 계정 정보 불러오기]에서 내정보.json 을 선택하세요.'
        } else {
            Say '자동으로 열기에는 데이터가 큽니다. 사이트의 [내 계정 정보 불러오기]에서 내정보.json 을 선택하세요.' 'Yellow'
        }
    } else {
        Say '파티 네비게이터의 [내 계정 정보 불러오기]에서 이 파일을 선택하세요.'
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
