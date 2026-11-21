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
$BuildLabel = '26752678'
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
# 실행 중인 게임의 Steam 빌드 번호(appmanifest 의 buildid). 경로는 진단에 넣지 않고 숫자만 쓴다.
function Get-GameBuildId([string]$ExePath) {
    try {
        $dir = Split-Path -Parent $ExePath
        while ($dir) {
            $parent = Split-Path -Parent $dir
            if (-not $parent) { break }
            if ((Split-Path -Leaf $parent) -eq 'common') {
                $apps = Split-Path -Parent $parent; $install = Split-Path -Leaf $dir
                foreach ($m in @(Get-ChildItem -LiteralPath $apps -Filter 'appmanifest_*.acf' -File -ErrorAction Stop)) {
                    $t = [IO.File]::ReadAllText($m.FullName)
                    $installMatch = [regex]::Match($t, '"installdir"\s+"([^"]*)"')
                    $buildMatch = [regex]::Match($t, '"buildid"\s+"(\d+)"')
                    if ($installMatch.Success -and $installMatch.Groups[1].Value -eq $install -and $buildMatch.Success) { return $buildMatch.Groups[1].Value }
                }
                return $null
            }
            $dir = $parent
        }
    } catch { }
    return $null
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
            if ($Phase -eq 'end') {
                $gameBuild = $null; try { $gameBuild = Get-GameBuildId $proc.Path } catch { }
                if ($gameBuild) { DiagAdd ('game build=' + $gameBuild + ' (도구 스키마 ' + $BuildLabel + $(if ($gameBuild -ne $BuildLabel) { ', 다름' } else { '' }) + ')') }
                else { DiagAdd 'game build=(확인 못 함)' }
            }
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
    if (-not $Pcap -and -not $script:GameSeen) { return '게임을 켜서 로비까지 들어간 뒤, 이 안내가 떠 있는 PowerShell 창(관리자 창)에서 Enter를 눌러 주세요(게임 화면에서 누르는 것이 아님)' }
    if ([SsMyInfo]::LoginAckFailed -and [SsMyInfo]::CaptureDamaged) { return '통신 기록 일부가 깨졌을 수 있습니다. 게임을 완전히 종료하고 도구를 처음부터 한 번 더 실행해 주세요. 그래도 실패하면 바탕화면 내정보_진단.txt 내용을 아카라이브 원글 댓글로 남겨 주세요' }
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
        public long Gaps, OverlapDiff;   // 진단: 빈 구간 수, 겹쳐 받은 구간에서 내용이 다른 바이트 수
    }
    sealed class Connection
    {
        public int Session; public bool Closed, Observed;
        public Dictionary<string, uint> Syns = new Dictionary<string, uint>();
    }
    public static string LastDiag = "";
    // 게임 흐름(시작 표식이 보인 흐름)에 빈 구간이나 내용이 다른 중복 조각이 있었는지(통신 기록 손상 의심)
    public static bool CaptureDamaged = false;
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
        LastDiag = ""; counts.Clear(); CaptureDamaged = false;
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
            if (f.Game && (f.Gaps > 0 || f.OverlapDiff > 0)) { CaptureDamaged = true; Count("game-flow-damaged"); }
        }
        var sb = new StringBuilder(); sb.AppendLine("pcapng bytes=" + d.Length);
        foreach (var c in counts) sb.AppendLine(c.Key + "=" + c.Value);
        order.Sort((a,b) => b.Bytes.CompareTo(a.Bytes));
        sb.AppendLine("TCP flows total=" + order.Count + ", listed=" + Math.Min(20, order.Count) + " (top 20, all ports/directions)");
        for (int i=0; i<order.Count && i<20; i++)
        {
            Flow f = order[i]; sb.AppendLine(f.Key + " session=" + f.Session + " bytes=" + f.Bytes + " packets=" + f.Packets + " SYN=" + f.Syn + " TLS=" + f.Tls + " game-header=" + f.Game + " gaps=" + f.Gaps + " overlap-diff=" + f.OverlapDiff);
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
                long gap = rel-cur; Count("gap-count"); Count("gap-bytes", gap); f.Gaps++;
                if (gap > 1048576) Count("gap-over-limit");
                // Never allocate or decode fabricated bytes across missing data.
                if (ms.Length > 0) output.Add(ms.ToArray()); ms.Dispose(); ms = new MemoryStream(); cur = rel;
            }
            // 겹친 부분은 먼저 받은 내용을 쓴다. 다르면 세기만 한다(어느 쪽이 맞는지 모르므로 고치지 않음).
            long chunkStart = cur-ms.Length, from = Math.Max(rel, chunkStart), to = Math.Min(rel+seg.P.Length, cur);
            if (to > from)
            {
                byte[] have = ms.GetBuffer(); long diff = 0;
                for (long k = from; k < to; k++) if (have[k-chunkStart] != seg.P[k-rel]) diff++;
                if (diff > 0) { f.OverlapDiff += diff; Count("overlap-diff-bytes", diff); Count("overlap-diff-segments"); }
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
        int pos = 4; byte flg = b[pos++]; byte bd = b[pos++];
        bool blockChk = (flg & 0x10) != 0, hasSize = (flg & 0x08) != 0, hasDict = (flg & 1) != 0;
        if (hasSize) pos += 8; if (hasDict) pos += 4; pos++; // HC
        byte[] o = new byte[Math.Max(1 << 16, b.Length * 3)]; int op = 0, blocks = 0;
        LastLz4Info = "lz4 flg=0x" + flg.ToString("X2") + " bd=0x" + bd.ToString("X2");
        while (true)
        {
            uint bs = BitConverter.ToUInt32(b, pos); pos += 4;
            if (bs == 0) break;
            bool raw = (bs & 0x80000000u) != 0; int sz = (int)(bs & 0x7FFFFFFF); blocks++;
            if (raw) { Ensure(ref o, op + sz); Buffer.BlockCopy(b, pos, o, op, sz); op += sz; }
            else Lz4Block(b, pos, sz, ref o, ref op);
            pos += sz; if (blockChk) pos += 4;
        }
        LastLz4Info += " blocks=" + blocks + " out=" + op + " in-left=" + (b.Length - pos);
        var r = new byte[op]; Buffer.BlockCopy(o, 0, r, 0, op); return r;
    }
    static string LastLz4Info = "";

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
    // 진단용: 경로 위 목록·사전의 (개수, 지금 읽는 순번). 예외가 나면 pop 하지 않아 실패 위치가 남는다.
    static List<int[]> DiagLists = new List<int[]>();
    static string ListSummary()
    {
        var sb = new StringBuilder();
        foreach (int[] x in DiagLists) { if (sb.Length > 0) sb.Append(" > "); sb.Append("[" + (x[1] + 1) + "/" + x[0] + "]"); }
        return sb.ToString();
    }
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
            var at = new int[] { n, 0 }; DiagLists.Add(at);
            for (int i = 0; i < n; i++)
            {
                at[1] = i;
                object k = DecodeValue(r, sc, kt, "value");
                object val = DecodeValue(r, sc, vt, "value");
                d[Convert.ToString(k)] = val;
            }
            DiagLists.RemoveAt(DiagLists.Count - 1);
            return d;
        }
        if (type.StartsWith("List<") || type.StartsWith("HashSet<"))
        {
            string inner = type.Substring(type.IndexOf('<') + 1, type.Length - type.IndexOf('<') - 2).Trim();
            int n = r.U16(); var l = new List<object>(n);
            object pv;
            var at = new int[] { n, 0 }; DiagLists.Add(at);
            for (int i = 0; i < n; i++)
            {
                at[1] = i;
                if (Prim(r, inner, out pv)) l.Add(pv); else l.Add(DecodeMessage(r, sc, inner));
            }
            DiagLists.RemoveAt(DiagLists.Count - 1);
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
                DiagPath.Clear(); DiagLists.Clear(); LastLz4Info = "";
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
                    LastDiag += "decode-fail-detail: 목록 위치 " + (DiagLists.Count > 0 ? ListSummary() : "(없음)") + ", " + (LastLz4Info.Length > 0 ? LastLz4Info : "lz4 없음") + ", 통신 기록 손상 의심=" + CaptureDamaged + Environment.NewLine;
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

    // CONTENTS_UNLOCK_TEMPLET.json:445-447, CT_SYNCHRO / NORMAL_BATTLE_CLEAR (SECTOR 3-15).
    const long SynchroUnlockStageId = 11003018;

    public static bool? SynchroUnlocked(object userData)
    {
        // NKM.Templets:25984,20118-20131: ud[6] = List<history>, entry[0] = stage ID.
        // NKC:540159-540163 replaces the entire history dictionary on login (no paging).
        // NKC:579633,539509 checks ContainsKey, not the three mission-star booleans.
        var ud = userData as List<object>;
        if (ud == null || ud.Count <= 6) return null;
        var history = ud[6] as List<object>;
        if (history == null) return null;
        bool found = false;
        foreach (object entry in history)
        {
            var row = entry as List<object>;
            if (row == null || row.Count != 4 || !(row[0] is long) ||
                !(row[1] is bool) || !(row[2] is bool) || !(row[3] is bool)) return null;
            if ((long)row[0] == SynchroUnlockStageId) found = true;
        }
        return found;
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
            // NKM.Templets:19987,20005: actual blossom state, never inferred from rarity/level.
            if (rec.Count > 14 && rec[14] is bool) u["blossom"] = rec[14];
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
        bool? unlocked = SynchroUnlocked(ud);
        if (unlocked.HasValue) link["unlocked"] = unlocked.Value;
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
        Say '  2) 로그인해서 로비가 뜨면, 지금 이 글이 보이는 PowerShell 창(관리자 창)으로 돌아와 Enter를 누르세요.'
        Say '     (게임 화면에서 누르는 것이 아닙니다. 이 창을 한 번 클릭한 뒤 Enter)'
        Say ''
        if ($auto) {
            $t0 = Get-Date
            while (-not (Test-Path $StopFile) -and ((Get-Date) - $t0).TotalMinutes -lt 15) { Start-Sleep -Milliseconds 500 }
        } else { [void](Read-Host '로비가 뜨면 이 PowerShell 창에서 Enter(게임 화면 아님)') }
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
