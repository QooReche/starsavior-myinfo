# 스타세이비어 내 정보 추출 도구 (설치 불필요: Windows 10/11 기본 기능만 사용)
#  - 캡처: Windows 내장 pktmon (게임 서버와의 통신을 "듣기만" 합니다. 게임·통신을 변경하지 않습니다)
#  - 해독: 이 파일에 내장된 코드(Windows PowerShell 의 기본 컴파일러 사용)
# 결과: 내정보.json (닉네임·UID·로그인 정보는 담기지 않습니다). 캡처 파일은 작업 후 자동 삭제됩니다(해독에 실패한 경우만 원인 분석용으로 남깁니다).
param(
    [string]$Out = '',
    [string]$Pcap = '',        # 이미 만든 캡처 파일을 해독만 할 때
    [string]$StopFile = '',    # 자동화용(이 파일이 생기면 캡처 종료)
    [int]$Port = 0,            # 0 = 자동(클라 서버 목록의 9300~9400, 10 단위 포트만 받고 해독기가 서버 흐름을 고름). 서버 포트는 업데이트로 바뀐 적이 있음(9340 -> 9390)
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
    if (-not $Pcap -and [SsMyInfo]::GameFlows -eq 0) { return '게임 서버 통신이 기록되지 않았습니다. 게임 업데이트로 서버 포트가 바뀌었을 수 있어 도구 갱신이 필요합니다. 바탕화면 내정보_진단.txt 내용을 아카라이브 원글 댓글로 남겨 주세요' }
    if ([SsMyInfo]::LoginAckFailed -and [SsMyInfo]::CaptureDamaged) { return '통신 기록 일부가 깨졌을 수 있습니다. 다운로드·방송 송출 등 통신을 많이 쓰는 프로그램을 잠시 멈추고, 게임을 완전히 종료한 뒤 도구를 처음부터 한 번 더 실행해 주세요. 그래도 실패하면 바탕화면 내정보_진단.txt 내용을 아카라이브 원글 댓글로 남겨 주세요' }
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
        public string Key; public int Port, DPort, Session; public long Bytes, Packets;
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
    // 해독기가 읽은 게임 포트(9300~9400) 흐름 수. 0 = 캡처에 게임 서버 통신이 없음(포트 변경 의심)
    public static int GameFlows = 0;
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
        LastDiag = ""; counts.Clear(); CaptureDamaged = false; GameFlows = 0;
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
        // 게임 서버 흐름(9300~9400 포트 또는 게임 프레임 표식)은 상위 20개 밖이어도 항상 적는다.
        // 0줄 = 해독기가 게임 포트 TCP 를 하나도 읽지 못함(캡처에 없거나 non-IP·malformed·조각 등 앞 단계에서 버려짐).
        int gameListed = 0;
        for (int i=0; i<order.Count; i++)
        {
            Flow f = order[i];
            if (!(f.Game || (f.Port >= 9300 && f.Port <= 9400) || (f.DPort >= 9300 && f.DPort <= 9400))) continue;
            gameListed++; sb.AppendLine("game-port-flow rank=" + (i+1) + " " + f.Key + " session=" + f.Session + " bytes=" + f.Bytes + " packets=" + f.Packets + " SYN=" + f.Syn + " game-header=" + f.Game + " gaps=" + f.Gaps + " overlap-diff=" + f.OverlapDiff);
        }
        sb.AppendLine("game-port-flows=" + gameListed); GameFlows = gameListed;
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
            // 보내는 쪽 묶음 처리(LSOv2)로 합쳐진 큰 패킷은 pktmon 기록에서 IP 전체 길이가 0으로 적힌다. 버리지 않고 캡처된 길이로 읽는다.
            // 이더넷 최소 프레임(IP 부분 46바이트)은 패딩이 섞일 수 있어 복구하지 않는다(LSO 패킷은 MSS 보다 커서 여기에 걸리지 않음).
            if (total == 0 && ihl >= 20 && end-pos > 46 && end-pos >= ihl+20) { Count("IPv4-length-zero-offload"); total = end-pos; }
            if (ihl < 20 || total < ihl) { Count("malformed-IP"); return; }
            if (pos+total > end) Count("IP-truncated");
            ipEnd = Math.Min(end,pos+total); next = d[pos+9]; Count("NextHeader."+next);
            if ((U16(d,pos+6)&0x3FFF) != 0) { Count("IPv4-fragment-unsupported"); return; }
            src = IP(d,pos+12,4); dst = IP(d,pos+16,4); t = pos+ihl;
        }
        else if ((d[pos] >> 4) == 6)
        {
            if (end-pos < 40) { Count("short-IP"); return; }
            int plen = U16(d,pos+4);
            if (plen == 0 && d[pos+6] != 0 && end-pos >= 60) { Count("IPv6-length-zero-offload"); plen = end-pos-40; }
            if (plen == 0) { Count("IPv6-jumbo-unsupported"); return; }
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
        Flow f; if (!flows.TryGetValue(key,out f)) { f = new Flow { Key=direction, Port=sport, DPort=dport, Session=conn.Session }; flows[key] = f; }
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
        // Bs.ServerLibrary PacketReader: ZigZag.Decode32((uint)ReadRawVarInt32()) — 32비트로 자른 뒤 지그재그.
        public long I32() { uint u = (uint)VU(32); return (int)((u >> 1) ^ (0u - (u & 1))); }
        public long I64() { return Zig(VU(64)); }
        public int U16() { return (int)(VU(32) & 0xFFFF); }
        public int Short() { return (short)I32(); }
        // 읽은 문자열 바이트 구간 [시작, 끝): 실패 진단에서 이 바이트는 가린다(닉네임 등 개인 정보).
        public List<int[]> Strs = new List<int[]>();
        public string Str()
        {
            int n = Short();
            if (n == -1) return null;
            if (n < 0) throw new InvalidDataException("string len");
            Strs.Add(new int[] { P, P + n });
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
            LastFieldStart = r.P; LastFieldType = ((string)fields[fn]).Trim(); LastFieldKind = kind;
            vals.Add(DecodeValue(r, sc, (string)fields[fn], kind));
            DiagPath.RemoveAt(DiagPath.Count - 1);
        }
        return vals;
    }

    // 가장 깊이 읽기 시작한 필드(예외가 나면 실패한 필드)
    static int LastFieldStart = -1; static string LastFieldType = ""; static string LastFieldKind = "";

    // 실패 진단용 원시 바이트(16진). 숫자 필드에서 실패했을 때만 남긴다:
    // 앞 = 실패 필드 시작 앞 최대 16바이트(이미 읽은 문자열 바이트는 __ 로 가림),
    // 뒤 = 실패 필드 자신의 바이트(클라 varint 최대 길이: int·enum 5, long 10). 그 뒤는 문자열일 수 있어 남기지 않는다.
    static string FailBytes(Rd r)
    {
        if (r == null || LastFieldStart < 0 || LastFieldStart > r.B.Length) return "(없음)";
        string t = LastFieldType; int max;
        if (LastFieldKind == "enum" && !t.StartsWith("List<")) max = 5;
        else if (LastFieldKind != "enum" && (t == "int" || t == "short" || t == "ushort")) max = 5;
        else if (LastFieldKind != "enum" && t == "long") max = 10;
        else return "(생략: 숫자 필드 아님)";
        int s = LastFieldStart;
        var sb = new StringBuilder("@" + s + " 앞");
        for (int i = Math.Max(0, s - 16); i < s; i++) sb.Append(' ').Append(InStr(r, i) ? "__" : r.B[i].ToString("X2"));
        sb.Append(" | 필드");
        for (int i = s; i < Math.Min(r.B.Length, s + max); i++) sb.Append(' ').Append(r.B[i].ToString("X2"));
        return sb.ToString();
    }
    static bool InStr(Rd r, int i) { foreach (int[] x in r.Strs) if (i >= x[0] && i < x[1]) return true; return false; }

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
                DiagPath.Clear(); DiagLists.Clear(); LastLz4Info = ""; LastFieldStart = -1;
                string stage = "본문 풀기";
                int bodyLen = f.Body == null ? -1 : f.Body.Length;
                Rd r = null;
                try
                {
                    byte[] body = f.Compressed ? Lz4Frame(f.Body) : XorBody(f.Body);
                    stage = "필드 해독";
                    r = new Rd { B = body, P = 0 };
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
                    if (stage == "필드 해독") LastDiag += "decode-fail-bytes: " + FailBytes(r) + Environment.NewLine;
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
        # 게임 서버 포트만 받는다. TCP 전체를 받으면 다른 게임 다운로드·스트리밍이 pktmon 기본 기록(원형 512MB, 가득 차면 오래된 것부터
        # 덮어씀)을 몇 초 만에 채워 로그인 응답이 지워진다(11/25 제보 «다른 게임 다운로드 중 실패»).
        # 포트 근거 = 클라 서버 목록(NKC: LiveKorea 9340·LiveJapan 9350·LiveGlobal 9380·LiveAsia 9390, 개발용 9300~9330) — 10 단위로 9300~9400 을 다 받는다.
        # pktmon 은 필터 하나에 -p 를 하나만 주면 «보내는 쪽이나 받는 쪽 포트»로 맞추고(두 개 주면 둘 다 가진 패킷만), 필터끼리는 «또는»이다. 최대 32개.
        [void](Pkt stop); [void](Pkt filter remove)
        $capPorts = if ($Port -gt 0) { @($Port) } else { @(9300, 9310, 9320, 9330, 9340, 9350, 9360, 9370, 9380, 9390, 9400) }
        foreach ($cp in $capPorts) {
            [void](Pkt filter add ('SSGame' + $cp) -t TCP -p $cp)
            if ($script:PktExitCode -ne 0) { Fail '캡처 필터 설정에 실패했습니다. 진단 파일의 pktmon 오류를 확인해 주세요.' }
        }
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
        Say '  2) 로그인해서 로비 화면까지 들어가세요.'
        Say '  3) 로비가 보이면 바로 이 창(지금 이 글이 보이는 PowerShell 창)을 한 번 클릭하고 Enter를 누르세요.' 'Green'
        Say '     ※ 게임 화면이 아니라 이 창에서 누릅니다.'
        Say ''
        if ($auto) {
            $t0 = Get-Date
            while (-not (Test-Path $StopFile) -and ((Get-Date) - $t0).TotalMinutes -lt 15) { Start-Sleep -Milliseconds 500 }
        } else {
            while ($true) {
                [void](Read-Host '▶ 게임 실행을 확인하고 로비까지 들어갔다면 여기서 Enter')
                $running = @(Get-Process -Name StarSavior -ErrorAction SilentlyContinue).Count -gt 0
                if ($running) { Say 'Enter 확인했습니다! 게임 실행 확인됨 → 내 정보를 가져오는 중입니다. 창을 닫지 말고 잠시 기다려 주세요.' 'Green'; break }
                Say '게임이 아직 실행되지 않은 것 같습니다. 게임을 실행해 로비까지 들어간 뒤 다시 Enter를 눌러 주세요.' 'Yellow'
                Say '  (게임을 이미 켰는데 이 안내가 계속 나오면 그냥 한 번 더 Enter — 그대로 진행합니다)'
                [void](Read-Host '▶ 로비까지 들어갔다면 Enter')
                Say 'Enter 확인했습니다! 내 정보를 가져오는 중입니다. 창을 닫지 말고 잠시 기다려 주세요.' 'Green'
                break
            }
        }
        Start-Sleep -Seconds 2   # 마지막 패킷이 캡처에 반영될 시간
        Say '마무리하는 중...'
        Record-GameState 'end'
        DiagAdd ('capture-end=' + [DateTime]::UtcNow.ToString('o'))
        [void](Pkt stop)
        if ($script:PktExitCode -ne 0) {
            # 종료 코드는 실패인데 실제로는 멈춘 경우가 있다(11/23 제보: exit=4201 «WMI 데이터 공급자가 … 인스턴스 이름을 인식하지 않습니다»,
            # 같은 출력에 «로그 플러시·손실된 이벤트 없음», 바로 다음 stop 은 «실행되고 있지 않음»). pktmon 문구 대신 ETW 세션 목록과 기록 파일로 판정한다.
            $stopCode = $script:PktExitCode; $stillRunning = $true; $queryOk = $false
            try { $stillRunning = [SsMyInfo]::IsCaptureRunning($etl); $queryOk = ([SsMyInfo]::TraceQueryCode -eq 0) } catch { DiagAdd ('capture-stop query-exception: ' + $_.Exception.GetType().Name) }
            if ($queryOk -and $stillRunning) {
                [void](Pkt stop)
                try { $stillRunning = [SsMyInfo]::IsCaptureRunning($etl); $queryOk = ([SsMyInfo]::TraceQueryCode -eq 0) } catch { $queryOk = $false }
            }
            $etlOk = (Test-Path $etl) -and ((Get-Item $etl).Length -gt 0)
            DiagAdd ('capture-stop recheck: first-exit=' + $stopCode + ' query-ok=' + $queryOk + ' running=' + $stillRunning + ' etl=' + $etlOk)
            if (-not $queryOk -or $stillRunning -or -not $etlOk) { Fail '캡처 종료에 실패했습니다. 진단 파일의 pktmon 오류를 확인해 주세요.' }
        }
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
