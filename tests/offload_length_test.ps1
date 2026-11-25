$ErrorActionPreference = 'Stop'
# 랜카드 묶음 처리(LSO/RSC)로 IP 전체 길이가 0으로 적힌 패킷을 버리지 않고 읽는지, 게임 포트 흐름이 진단에 항상 찍히는지 시험한다.
# 합성 pcapng 만 쓴다(실제 캡처·계정 정보 없음).
$root = Join-Path $PSScriptRoot '..'
$text = Get-Content -Encoding utf8 (Join-Path $root 'myinfo.ps1') -Raw
$src = [regex]::Match($text, '(?s)\$src = @''\r?\n(.*?)\r?\n''@').Groups[1].Value
if (-not $src) { throw 'Embedded decoder not found' }
$test = @'
public static class OffloadTest {
    static System.IO.MemoryStream ms = new System.IO.MemoryStream();
    static void W32(uint v) { ms.Write(System.BitConverter.GetBytes(v), 0, 4); }
    static void Block(uint type, byte[] body) {
        int pad = (4 - body.Length % 4) % 4; uint len = (uint)(12 + body.Length + pad);
        W32(type); W32(len); ms.Write(body, 0, body.Length); ms.Write(new byte[pad], 0, pad); W32(len);
    }
    static byte[] Packet(uint seq, byte[] payload, int ipTotalOverride) { return Packet(seq, payload, ipTotalOverride, 9390, 9304, 2); }
    static byte[] Packet(uint seq, byte[] payload, int ipTotalOverride, int sport, int dport, byte srcHost) {
        var p = new System.Collections.Generic.List<byte>();
        p.AddRange(new byte[12]); p.Add(0x08); p.Add(0x00);           // 이더넷, IPv4
        int total = 20 + 20 + payload.Length; if (ipTotalOverride >= 0) total = ipTotalOverride;
        p.AddRange(new byte[] { 0x45, 0, (byte)(total >> 8), (byte)total, 0, 0, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, srcHost, 10, 0, 0, 1 });
        p.AddRange(new byte[] { (byte)(sport >> 8), (byte)sport, (byte)(dport >> 8), (byte)dport });
        p.AddRange(new byte[] { (byte)(seq >> 24), (byte)(seq >> 16), (byte)(seq >> 8), (byte)seq, 0, 0, 0, 0, 0x50, 0x10, 0x10, 0, 0, 0, 0, 0 });
        p.AddRange(payload); return p.ToArray();
    }
    static byte[] Packet6(uint seq, byte[] payload, int sport, int dport) {
        var p = new System.Collections.Generic.List<byte>();
        p.AddRange(new byte[12]); p.Add(0x86); p.Add(0xDD);
        p.AddRange(new byte[] { 0x60, 0, 0, 0, 0, 0, 6, 64 });        // payload length 0(오프로드), next=TCP
        var a = new byte[16]; a[0] = 0xfd; a[15] = 2; var b = new byte[16]; b[0] = 0xfd; b[15] = 1; p.AddRange(a); p.AddRange(b);
        p.AddRange(new byte[] { (byte)(sport >> 8), (byte)sport, (byte)(dport >> 8), (byte)dport });
        p.AddRange(new byte[] { (byte)(seq >> 24), (byte)(seq >> 16), (byte)(seq >> 8), (byte)seq, 0, 0, 0, 0, 0x50, 0x10, 0x10, 0, 0, 0, 0, 0 });
        p.AddRange(payload); return p.ToArray();
    }
    static void Epb(byte[] pkt) {
        var b = new System.Collections.Generic.List<byte>();
        b.AddRange(System.BitConverter.GetBytes(0u)); b.AddRange(new byte[8]);
        b.AddRange(System.BitConverter.GetBytes((uint)pkt.Length)); b.AddRange(System.BitConverter.GetBytes((uint)pkt.Length));
        b.AddRange(pkt); Block(6, b.ToArray());
    }
    static void Check(bool ok, string m) { if (!ok) throw new System.Exception("assertion failed: " + m); }
    public static string Run(string path) {
        var shb = new System.Collections.Generic.List<byte>();
        shb.AddRange(System.BitConverter.GetBytes(0x1A2B3C4Du)); shb.AddRange(new byte[] { 1, 0, 0, 0 }); shb.AddRange(System.BitConverter.GetBytes(-1L));
        Block(0x0A0D0D0A, shb.ToArray());
        Block(1, new byte[] { 1, 0, 0, 0, 0, 0, 0, 0 });               // linktype 1
        byte[] a = new byte[1400], big = new byte[3000], c = new byte[100];
        for (int i = 0; i < a.Length; i++) a[i] = 1; for (int i = 0; i < big.Length; i++) big[i] = 2; for (int i = 0; i < c.Length; i++) c[i] = 3;
        Epb(Packet(1000, a, -1));
        Epb(Packet(1000 + 1400, big, 0));                             // 묶음 처리 패킷: IP 전체 길이 0
        Epb(Packet(1000 + 4400, c, -1));
        Epb(Packet(9000, new byte[10], 5));                            // 진짜 손상(길이 < 헤더)은 계속 버린다
        Epb(Packet(9500, new byte[6], 0));                             // 최소 프레임(IP 46B, 패딩 섞일 수 있음) + 길이 0 은 복구하지 않는다
        Epb(Packet6(500, big, 9390, 9305));                            // IPv6 payload length 0 오프로드
        for (int k = 0; k < 21; k++) Epb(Packet(1, new byte[1000], -1, 40000 + k, 443, 7));   // 게임 흐름보다 큰 다른 흐름 21개
        Epb(Packet(77, new byte[50], -1, 50000, 9390, 9));            // 클라이언트 -> 서버 단독(목적지 포트만 9390, 22위 이하)
        System.IO.File.WriteAllBytes(path, ms.ToArray());
        var streams = SsMyInfo.ServerStreams(path, 0);
        string diag = SsMyInfo.LastDiag;
        Check(diag.Contains("IPv4-length-zero-offload=1"), "offload counted\n" + diag);
        Check(diag.Contains("malformed-IP=2"), "real malformed and padded minimum frame still dropped\n" + diag);
        Check(diag.Contains("IPv6-length-zero-offload=1") && !diag.Contains("IPv6-jumbo-unsupported"), "ipv6 offload counted\n" + diag);
        Check(diag.Contains("gap-count") == false, "no gap after offload packet\n" + diag);
        var v4 = streams.Find(x => x.Length == 4500);
        Check(v4 != null, "one contiguous 4500B IPv4 stream");
        Check(v4[1400] == 2 && v4[4399] == 2 && v4[4400] == 3, "offload payload placed");
        Check(streams.Exists(x => x.Length == 3000 && x[0] == 2 && x[2999] == 2), "ipv6 offload stream 3000B");
        Check(diag.Contains("game-port-flows=3"), "three game port flows listed\n" + diag);
        Check(diag.Contains("[10.0.0.2]:9390 > [10.0.0.1]:9304"), "server flow listed\n" + diag);
        Check(System.Text.RegularExpressions.Regex.IsMatch(diag, @"game-port-flow rank=(2[2-9]|[3-9]\d) \[10\.0\.0\.9\]:50000 > \[10\.0\.0\.1\]:9390"), "dport-only flow outside top 20 listed\n" + diag);
        return "offload zero-length IPv4 + game-port-flow diag";
    }
}
'@
Add-Type -TypeDefinition ($src + "`n" + $test) -Language CSharp -ReferencedAssemblies 'System.Web.Extensions'
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('ss_offload_test_' + [Guid]::NewGuid() + '.pcapng')
try { Write-Output ('PASS ' + [OffloadTest]::Run($tmp)) } finally { Remove-Item -Force $tmp -ErrorAction SilentlyContinue }
