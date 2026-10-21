# 스타세이비어 내 정보 추출 도구 (설치 불필요: Windows 10/11 기본 기능만 사용)
#  - 캡처: Windows 내장 pktmon (게임 서버와의 통신을 "듣기만" 합니다. 게임·통신을 변경하지 않습니다)
#  - 해독: 이 파일에 내장된 코드(Windows PowerShell 의 기본 컴파일러 사용)
# 결과: 내정보.json (닉네임·UID·로그인 정보는 담기지 않습니다). 캡처 파일은 작업 후 자동 삭제됩니다.
param(
    [string]$Out = '',
    [string]$Pcap = '',        # 이미 만든 캡처 파일을 해독만 할 때
    [string]$StopFile = '',    # 자동화용(이 파일이 생기면 캡처 종료)
    [int]$Port = 9340,
    [string]$Page = 'https://qooreche.github.io/starsavior-party-navigator/',   # 끝나면 이 사이트를 열고 데이터를 넘김
    [switch]$NoOpen
)
$ErrorActionPreference = 'Stop'
$BuildLabel = '25951618'
$auto = [bool]$StopFile

function Say([string]$m, [string]$c = 'White') { Write-Host $m -ForegroundColor $c }
function Pause-End { if (-not $auto) { Write-Host ''; [void](Read-Host '엔터를 누르면 창이 닫힙니다') } }
function Fail([string]$m) { Say ''; Say ('[오류] ' + $m) 'Red'; Pause-End; exit 1 }
function Pkt { $o = $ErrorActionPreference; $ErrorActionPreference = 'Continue'; & pktmon @args *> $null; $ErrorActionPreference = $o }

if (-not $Out) { $Out = Join-Path ([Environment]::GetFolderPath('Desktop')) '내정보.json' }

# ---------- 관리자 권한 (캡처에 필요) ----------
if (-not $Pcap) {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Say '관리자 권한이 필요합니다. 잠시 뒤 나오는 "이 앱이 장치를 변경하도록 허용" 창에서 [예] 를 눌러 주세요.' 'Yellow'
        $a = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -Port {1} -Out "{2}" -Page "{3}"' -f $PSCommandPath, $Port, $Out, $Page
        if ($StopFile) { $a += (' -StopFile "{0}"' -f $StopFile) }
        if ($NoOpen) { $a += ' -NoOpen' }
        Start-Process powershell -Verb RunAs -ArgumentList $a
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
    static readonly byte[] StartMagic = { 0xDD, 0xCC, 0xBB, 0xAA };
    static readonly byte[] EndMagic = { 0x44, 0x33, 0x22, 0x11 };
    static readonly ulong[] Masks = { 0xC4A975489AA72956UL, 0xD7C1A29E30FAE47BUL, 0xDCD6D3F2CCC0DEF9UL, 0x3063872F85428EFCUL };

    // ------------------------------------------------------------------ pcapng + TCP
    sealed class Seg { public uint Seq; public byte[] P; }

    // 서버(serverPort) -> 클라이언트 방향 TCP 흐름들을 재조립해 돌려준다.
    public static List<byte[]> ServerStreams(string pcapPath, int serverPort)
    {
        byte[] d = File.ReadAllBytes(pcapPath);
        var link = new List<int>();
        var flows = new Dictionary<string, List<Seg>>();
        int off = 0;
        while (off + 12 <= d.Length)
        {
            uint type = BitConverter.ToUInt32(d, off);
            uint len = BitConverter.ToUInt32(d, off + 4);
            if (len < 12 || (long)off + len > d.Length) break;
            if (type == 1 && len >= 20) link.Add(BitConverter.ToUInt16(d, off + 8));
            else if (type == 6 && len >= 32)
            {
                uint iid = BitConverter.ToUInt32(d, off + 8);
                int cap = (int)BitConverter.ToUInt32(d, off + 20);
                int lt = iid < link.Count ? link[(int)iid] : 1;
                ParseTcp(d, off + 28, Math.Min(cap, (int)len - 32), lt, serverPort, flows);
            }
            off += (int)len;
        }
        var result = new List<byte[]>();
        foreach (var kv in flows)
        {
            var segs = kv.Value;
            uint first = segs[0].Seq;
            segs.Sort((a, b) => unchecked((int)(a.Seq - first)).CompareTo(unchecked((int)(b.Seq - first))));
            long cur = 0;
            var ms = new MemoryStream();
            foreach (var s in segs)
            {
                long rel = unchecked((int)(s.Seq - first));
                if (rel > cur) { ms.Write(new byte[rel - cur], 0, (int)(rel - cur)); cur = rel; }
                if (rel + s.P.Length <= cur) continue;
                int trim = (int)Math.Max(0, cur - rel);
                ms.Write(s.P, trim, s.P.Length - trim);
                cur = rel + s.P.Length;
            }
            result.Add(ms.ToArray());
        }
        return result;
    }

    static void ParseTcp(byte[] d, int pos, int cap, int linktype, int serverPort, Dictionary<string, List<Seg>> flows)
    {
        int end = pos + cap;
        if (linktype == 1)
        {
            if (cap < 14) return;
            int et = (d[pos + 12] << 8) | d[pos + 13];
            pos += 14;
            if (et == 0x8100 || et == 0x88A8) { if (cap < 18) return; et = (d[pos + 2] << 8) | d[pos + 3]; pos += 4; }
            if (et != 0x0800) return;
        }
        else if (linktype != 101) return;
        if (end - pos < 20 || (d[pos] >> 4) != 4 || d[pos + 9] != 6) return;
        int ihl = (d[pos] & 0x0F) * 4;
        int total = (d[pos + 2] << 8) | d[pos + 3];
        int ipEnd = Math.Min(end, pos + total);
        if (ihl < 20 || pos + ihl + 20 > ipEnd) return;
        int t = pos + ihl;
        int sport = (d[t] << 8) | d[t + 1];
        int dport = (d[t + 2] << 8) | d[t + 3];
        if (sport != serverPort) return;
        uint seq = ((uint)d[t + 4] << 24) | ((uint)d[t + 5] << 16) | ((uint)d[t + 6] << 8) | d[t + 7];
        int doff = (d[t + 12] >> 4) * 4;
        if (doff < 20 || t + doff > ipEnd) return;
        int plen = ipEnd - (t + doff);
        if (plen <= 0) return;
        var p = new byte[plen];
        Buffer.BlockCopy(d, t + doff, p, 0, plen);
        string key = d[pos + 12] + "." + d[pos + 13] + "." + d[pos + 14] + "." + d[pos + 15] + ">" + d[pos + 16] + "." + d[pos + 17] + "." + d[pos + 18] + "." + d[pos + 19] + ":" + sport + ">" + dport;
        List<Seg> l;
        if (!flows.TryGetValue(key, out l)) { l = new List<Seg>(); flows[key] = l; }
        l.Add(new Seg { Seq = seq, P = p });
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

    static object DecodeClass(Rd r, Schema sc, string cn)
    {
        object o;
        if (!sc.Classes.TryGetValue(cn, out o)) throw new InvalidDataException("class not found: " + cn);
        var desc = (Dictionary<string, object>)o;
        var fields = (Dictionary<string, object>)desc["fields"];
        var order = (object[])desc["order"];
        var vals = new List<object>(order.Length);
        foreach (object po in order)
        {
            var pair = (object[])po;
            string fn = (string)pair[0], kind = (string)pair[1];
            vals.Add(DecodeValue(r, sc, (string)fields[fn], kind));
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
        int streams = 0, frames = 0;
        foreach (byte[] s in ServerStreams(pcapPath, serverPort))
        {
            streams++;
            foreach (Frame f in Frames(s))
            {
                frames++;
                if (f.PacketId != 403) continue;
                byte[] body = f.Compressed ? Lz4Frame(f.Body) : XorBody(f.Body);
                var r = new Rd { B = body, P = 0 };
                object obj = DecodeClass(r, sc, sc.PacketClass);
                if (r.P != body.Length)
                    throw new InvalidDataException("해독 불일치(" + r.P + "/" + body.Length + "): 게임이 업데이트되어 도구도 갱신이 필요합니다.");
                info = "stream " + streams + ", frames " + frames + ", body " + body.Length + " bytes";
                return obj;
            }
        }
        info = "streams " + streams + ", frames " + frames;
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
        var js = new JavaScriptSerializer(); js.MaxJsonLength = int.MaxValue; js.RecursionLimit = 200;
        return js.Serialize(root);
    }

    // PowerShell 에서 한 번에 호출
    public static string Run(string pcapPath, string schemaJson, string buildLabel, int serverPort, out int unitCount, out string info)
    {
        unitCount = 0;
        object ack = DecodeLoginAck(pcapPath, schemaJson, serverPort, out info);
        if (ack == null) return null;
        string json = Export(ack, buildLabel);
        var ud = A(A(ack)[2]); unitCount = ((Dictionary<string, object>)ud[1]).Count;
        return json;
    }
}

'@
$schemaB64 = 'H4sIAAAAAAAC/+296Y4bV5Yu+ioX+m1cMBiMINk4EMBMUimWMkk2B9nqQiOhslVdQrvsupbcF4VG/4w5HscP5Ec5e45v7SFyM6Wuc4BzAMFOkmtH7GHtNQ//+eJPv3788YcX//Rimi2zJE8WL7558f2P7z99+vDpxT/954vff2t//62Ef/3vvzW//1b//lv1+2+d+FgLGP49H/Dnjx9+/EENrcSPtfhR/uvEl/KRtfhYyC/ZBD7+9Jm9WwBU4vtavKrS/2o6hD2hU6P+65sXP//yw4dfXvzTH/945Wu/efEf73/89cOLf/3mj1e+2oz81//is240YCP+lfp1rX57J/5uxKzpNhXiXyn+Kwd1ElDP2kylgW2S6yv1muTHQg+Rz1ELgFGNnkhvViL+rvQcG/2xZ6P+9PPPP9q7e81s6e5eM2M68ppZW+diposzK+FQenNwHvSVa6w0nnd64gWM4zBsrwRkoSda6vcUemyN79QnWMO1kg9s9GrNbqmz+PT5l48//ZsY2GtcLPUTKj2qg9nW8obo5db6Fa2eWwMbJx9Vee5S9B588+LDT7/+dTjs6MXRw75mde5hl/ocCjjgHk5ankllH3av32HW1Ouly1m3+u+SHgZuZac3wyBpq8lJJw8DBnYaHudolt1o0lHL41+///zh/PGvH/RQ6wQL8Ueht6s2o3GodbbXLNmhk9FrpiOvWbQzMnrNFlp0+uGFxlrzgBKQu/DQALMLnQYxZKfRnFACFGynf/xZnW2pJ9UBApvL0Gma1Q7E2Tqba95L9+maV1v7ZC51AbSy0LcNqVpp71OnwXsNaLDD4FKtb94LYKfmDb1+Z0uljeL/BdSoAIMafaQtXPnyhaIDNfDjWo8186sN7/Bv/zXLIWTvmjdbu1/q1df6vzUwK4OlnWf3zWbhNa5hWzuzBrH7FXDSFjaz1jej1vCVpjclcLAakYieYqc5YQuiomGDpYY0O1jq61LAsfb0XwHIWzuyTAPoUYJg0sC/mspNhhu3sLsl4J96NYzqNLLVetN64C8FcBZ8V09lUHMK5o4OJJgKwD2IoC2IoAWVKVq6GyWInrWzh+ZYSznqj/9qY/01aOQQ52gEcchV9NH7hMK443cE0WgUcNYZjQaOVBONCg6zjUYHZ4eiUcIiRr2eUAmXtdXb3QFO+FhBB2JBCZJnBfyol8TCsMxeI4KhQIWmmYWmGb1WoF7cf/z0+X8wJH6pb0wH5230kI6Szl5yn5A8dM3EncONnrtzuNEzd4+o0L8bvGgBkQZGah9RrRfS0gtgELPX87AoTAWXpAM6gRvQSi4jTggYfQM404JMYfTG9qV9INdM08H86Km6QlDtqJUllYMKzVV89g5zYxrn4vb6vyVsa0nRrgLVpQKW2cnDECr5oD5UYGro9eYY7UfJtTjMkNmSCitGea30rz0Oa0HfN6jaAF83Yng7ZpSJ2xuHQ0Tvj0/ZiNsih0NE7xIdec1GuZjXgbxYU4Ef963xmJBQje8puW4RmbX4XQDjNTvYU7XBCNQN8NQeTAIliLilUXKBMaJI31HTmpqYx74UvRTn0kdPUgvtcuevkVe/GrerqV3RKKaNfmNp9EqwGrRUEUMhqIWbUcL7viabi560cyuiZ+0aVjt9mEbSK0A37gH1HDbXAMo0GssL0H16Y3++Vimt9A6YiZWUZRmO12uCbVh2DepeBzjbmjsEKkQF4kQH2NlTi2vjM/M2IBU3cNeHvaBKjhETO2r4a2BRxTDKZdjRG07U5mv2xsHJ6P0JGJUj9sjhK9H75JqiOhBDClhiaRFhP41Hab7Ql6nWKy0MyYB7UYOJpAKTrtmfXgvRLXV7tKDwGJtSLVVcasjs4RLXYN5FAViZTqnkjhpcR70JqO4okenTX37+BVEVXSwldTAYWm82w6iTRqNsAV0NeSr8DClu3x3hPnpHHQyL3lKfhhq3oT6sjttS13TV0smVVJwxWnLxjzUcllR9RvqElt9Wyzk13e4OJL4G5LKSKkYt8MIOlOUOVqXwi1yAr2V0vGbWPmk1buZeY3GcCOk1qjeAxR1IXw3IIT1RJEvw4RaAzA3ILBzNXr4YPH8tWGwKgCuB/tXDWzrqc0J11dwmdade6rOvQB4x8y/Ay6hOg7ylcixmNb0pynxg1lJRimPYTQFKCmIY8MLGIQId3AI+k5daE23oPzRwGR6plDyi4FfgBWoAETvwv5cv/V6OOESgiHvN4TooH31gzjujD8FRYaM31iWtDRj9Wti0DjQdn++qhedWIDl3cI2UTj4c5xWk3DnOa17otbrU1PbVg53GOEWa/0OsLv/n2U+MLl6BFaSk9v0aKPMXSsjgbnme3FuChbGghvWOGjEKR+4121nAWwpKDhSN8qta/yuk0msW7BDd6OW6MR1oj21BmWnBxCZ9aI5sWQJpqSHCiFAUebKgrLZAy01oU4EE+IUdblIBQ6lobEIPAULRoXQDghVUqe4gHsa8sQy6saM3wOF10UvzIUncpF3lOFYs8vA6600Y6NGjncCK0+gpz0PfjW29AxeyEX07+hrjR1eikKMlVFRFq6mn1RgZhymau9pT90dtGSYlEiPH6cBdZ4W94MHWYBGOi/34BoMskfiYSL4aOERBZMXYl6Dc29PgL3R/Gp3U4u1fFn1zDTY52B+NUA7LjEYqnxIXh1jOyGjccmYbjV4O+4lGHJ/8HYcMXy0mqgVfTOkEzJRoWPHQJDQHdiCmoZm4osYEtFSUIBXXNFaiokJMA+ZVFMPxPFX0UUDAvGa2PmEvbsa+AIW4WVvnUlG3QQkGgg6uUenhFY0To1JQDDLBEcQF2oNCUlC5B4OMa4sQo60XeVkP9K8wXnNUNAqQ8dGYW4LWqyjftXaxBh5R0dDIElxwvQ4Aq0EKb6nS2wGvbi21xxIEMA7Z4FRt4rrMsAooiBUE3EJISwXDXMNC9BH74nTiTtk3Mu6gHT0r+qw9QdZxx+ILu4o7GZ/6EHc43gjHGl5aAt+ocNKeCMeK8sIODKaoz1iRdM9IQOlBVS2APRgJ2uBVPxJNdM2MAxzy6vyVa2bu0tMWdP0G5BgTDdfqrXLU7hoW2wKjtLC5+mIhuoNg/h7e1YNVTaGxL6KyBFtcQQWObkwgvGaJX0usu2apgYjBiOW64k4PBm/LDYEJUY0ng6ICauVKn/XgbxyOpgCsRbGzdIIqe8dmg3EaNQ3PMqfVUw2spQGYPdimShBGiJJoRWJb6QMdnEVr6ZYNSE0l5UQVRFdanvsaDCwV0NOGRlBYQc0tWNFbEAaQEVS2B2pwwTbA6GoI1GnBvdQRTa6ifKak5MdY+lwz8TWI4mgA0cji41pxCOMLXYlDGl+YcRze+PwFcajjSNTR6OPMNhqFfC7nOARyjXsVuGJLGizbI/nykBvDmNB4YHKLjKnLFsc7KoZgJFMBikdhieMY8lFRV2cPB0Sk+AbslC2QfmNdHES/gCR7zTJ9eXRxKx2NbxldrIN+0et1PUCx/l2/P7mEmA6jAbXAYGsdDHK1rtQDsy/gQEoI8FRXispbPbgje7DRFCavj9J9FMU7uOwdCAxS32soBaso9e3gXRWkC3dgC6nAmN7CFtjWxw6OvAHbQGWlqAXCDa85HKLcXLOPPiIYt5e2PhW9SQ6XiN4nV/LuwHZSUCKMi2/8SasVNa7X4BccXAxUWCgh59FydjQYFeKXhq95rcNkol/t0ocW9KbS0R+boPL4vHSHipKi0onZM4KOpTw24DLpIWikAcRrnbT8AiLRCsr7MPyq9bkSexo2bu5GRe2UBXHzx6riXzEt45otdZhZ9LYGWFLE1jp3OnpjXUsH0uKaijkYhtZ7mJkVbFRSB3ptl794Jp3+Aq7Q0Yh8rP7QWzd5xEJyzUq/ArX9Qgp/zZq9pKsGwt5QfR5lTse2UoJ5vaDp38hbO5Q7Cxri2AJtbigf7Fx7bQmKfgnhYjWw687yNRbgPcc0L4z76cD5MJjwS3B7YyhugVzFEsVLagzrIEugBzNmb63ty5yC1xyFo7ZGn4bPTBt3IGG701Nn4hDp6GPxZQHHncxXc9Bdk8vuGpUbOkeMr2rBA9U/Q28owCzegt28cXKIC8ixurrUBHqWe7r+EiJtCuovLCmfx9DEDuyLhVPupAEVvYLYxBbSgypzjZxyJ+gJsawp5tzdRBb0TBUUScx/C8oNG+ppxlx0jDLs6Lt6x2mDKzViTkGl6crKbQG+UsA0SmrHxuj+Eoz6PYgMVo4/po604Byy7NEt3cOSxtF01GpVYQ4LFWTRUtxg6QqILbbWVYC6Yhnpeli1W7ugh/mUTka1MXs0dimcnoamYrWNmpK9yjLMoLjaAVL1YJurLCZSUA2ygnl3QD1kiqZ1bVAKqClF7JFe4+XGqksdNTi2ECbV0EPoKfpjtAIG2RYGTf74r/ptKNZU1BWKIQDdSAmJaJJqa/vPLHhzDQH0BevEEUGfUhFHBQMxtRFk0JevFkcKA2E+EeTQeWc0SXTkj2iy6POGx5FGn8csjjw6mBBNIn2lH+LIpM+ZEUcqfacSRy59NuE4aunDvjiC6awzmmb67HhxRDPgAY2gmwFDQwTtdN4ZTT29pTzQioImsh7S8DqPCbAG75l1bUqMsrYYy/NKcz4vVL6hRBmvckdpZ+/EcXZgK8ayg5iqYwl/JaQ/tlSFagLFpHpqf2rAedLQWo6NjhWvgfGgpba2UqwgHreiFlJUwzoMUKYWPkxYbeH5Bd2TjuRlXRHQ8VLvQAn50BXcuQ4oROn47wsaFdvRdI2Bw3oTYjqwAKHfydy01hLbepq5UsGWN0ALK8iBrhzxooEyCD3k6GPsbuMrFTpkOjqnhDJBT9GhB69bZRVlJNcDS2xaBQ7cOmEoONT0VAvKVYqgHT+adnytEKXnZ59cQ0N81oU4OuLLW4mjJT4+EkdPfKHVcZTCJ8/G0QlnttF335eIGXf/AzliESTAJ//EUYHAOiPud1jif+p2B/A24nL77GlxF9ytmoLlVXoqGaIHpwyWPC0Bixpau7nQkdXhbPZrHuOKQxXgLub0tsBzC4/3BHER63pgvkBhCiGhOISO4o7WKGogR6G0TNE9dfDUYD9FalXrupsV1Q4aECsLFJFp2ndDVQwMT65IluBgEcRF97AAdEQ1TinjDq5QTWMIMYdPykCdL4O6olFDLeQM9bQySw2Cb2nVJXrW8ysrOIXqbzXGQlm1zVqaporVkHr4o3QsqEiKMD+FVJnTAmN0qNMg6hRgxGgozRkcV/TsO6p74H9LWobesvWV1F9QgM2lg8pjrthTAobVtIJhh0KXM9a63D3F1wZWaiXsummaaN0wQQT1WO5sHJHwlWuMoxOBaN4IUmFXFI6mAT7DWBwd8C0zjhD4zCFxV9ynssddXl+EZtz99QlMcXfYJ4LE3c5AWF7EDfXtbdwt9eVZxd1RXx5w3A314VDcLfUWny2c8sEFiBSNjoZxzCGYv1jRBgw1ZB/XPmpkJbd0kO2MiUH9mOBzzRR8CY5xE3ADTqJbPPxv7QVt6am32GECYpCVPWH98fvPH3/+6f0vf+dH8c3/84yiNw2NQMcadJbSB2WCrjDYWaV1Oto3oaJ5X8FlXVVlZxAEGiCbFYypMd8STjWu+OjgK8I6YQUVzIizdIg6iw2LeglmIqRUWOYHlYuS5CbE1pJ5Ca5pbNyDCdQVRJz1Wi7FpL6GVlZogC90YBlC3bOEa1mgwUXXicCqEy01mbRw3u2Lob9F6zjOkCIUptDP6/ef/nL68Pl/SMEfYwgtHoGB4hBN7CSpFjTEvIVh5pLYRXSwjiiWbe+pb4nWzIqtnPgSQuIqgCipEcaIJVD+6IrqMy8haqOGHM2eHl2NYjpcbK57KoJ1dS2wEjh+DXwWqQxd1xWdccxbWrpRNbULVRgKRtNMOtg4bNtSmMA6QOqeSkI17F5hlK7Bpt3QvhoNmLYKTE/AVZS0DHAB7kiTo97oTkk1WFl64ObY66rQUfVIuKwQd7RXYJZ2dBDzUDMEmbtV6bTEeAMwF5Vg+bEk6wI05gJCaVu6RTUgTacNGK1lmKMErLVqRAIfr0FnaGl9wqEE2XU17QeRrQZBoqc3amg1pg0wBY1SbsGfjgbwmqYCN7RXUkNrYpVWoCtJma9oz7IWzLOlSavjw05/e/+TQ1NKWn+iocJlYQ9tYVcLWl2jAaJegoMkus/DNxgE2dEEgAo2v3BqWjTUbdzSgvqoPwVC1LGSGFYPU1ziJY0wQ9bfwD506MC6Ts0Y9rZzzJIlhn6aYOlBUowtPPsSrHc9pVEFDREoTBAOoHSFMhpNHB5CF2ihzh5i41Hoa42FdBCpWtrbq4d7XMKRlkh4KxB2OsgL6LGcij6LhqZFFsBTkK52NHC9cGzhDbVWlJpwRZdx+Qaz93sq/qDvpvRFEKJLoaR5pwXKHmDgLGjfj9pJuiuAnDZOUE0PSDtcdivQGtOuKmqdqX2+56saWuKR93BmPSh7HVDPgsglsSXXXkJoZ0Hrgte0U1BjDJyQilQ4d7GkJokSogc66qcogWOZU/GFIpY0+KsGKoGUuyVUrnfIPRbUG8JcjCbZ0gCwnpbtMDy60nZnzFnpQR62SqZioqBluGho2mllcJioXFFNU15Sz0lBM0AaGvld+sIhKrCDWQkgFa0/bJpR1BB3VDhpqi2ae6kNscXkDJqDVBA6f0WZwpdQF6il0h3GZ1S+sqXYdLMFK4qVy9JAqmtLZ1CBYodkHVXJEkZZTGGIqSJKU2zRiJcgG3W0em9LCU5hHDVENescnjCEd8JN+VphqdeYo3zBa3F2pUC14Ahbkc+2HGf08QWvxZlzfG78OBONLxQ2zuzic8bHGVScd0abSnzZgHEmEl9Aa5yVxDfbOEOJL0Muzvjh66ITZ9AI1AyNMEw4I6ONDT7fT5wZwffOONOAr4J4nNLvq9QYp877goXjFHVfOlecCu5zR8Qp14E6VBFqs69mSpzWHMbbp5Rm312J05l9GB+nDQc8chEacSCBIELL9a0zTn/1eZLjdFIf9sVpm777GadBBnJ8I3RDh/NGa32BhoMRmp+P88bpdL6RcWqdb2/jVDVfKkmc+uULpYxTrHxBe3F6lXOe0bqSD4fitKBAoEeEZhNIvI3Qa3zhuHEai69oZZwW4uNIcZqIT6qJ0zF83CFOb/AGRDa093xJi44FYgqsGp4lJfeYFmXlanaOlFHQnW2cOg4l3NouUBujM/bboR9WSV2pFS1biuXbRWbGn/7++QPEkFcQb9PC6WB/9cqJwKqpUIkVw4aK/nRtGJ5bg7ulsUr5OrUbC9psrwVNrvZZnK2s8QbOuqSh0N0zy5O7/TmikcTH0OMQxdfZIw5ZfIwuDl18MclxCBOInYtAGt9s4xDHF1QWhzw+VToOgbx9XKNiNTykpqJdUiuwUBKm8sV5Us/uYnBtOwL3pkSv8WvlcXxRcf3rS+SbMLboBozeGPyO5mZiQVjjimm1ma+mdbl6Wh6JdF56Tqccb3R/3ATtcNbr+9bgfjY0uquhdvzC32UQ2yCiyIE0ZUg3A5nbqkla0vxZk933JeZsjEDFhu89DXfH3APXuhm9uq8lrF4za7fGcLQ93m2p0IP7safFXmrI4mnA/B1XecnthxD9qpE65094rr9O9a+Cmr0asECUtFJRH7zOzyzFdc2r3eKv0e2WvIUP0e5b0mwyYyioHN5V0jYHLdjrhmxEq9oZFq7DfK6etkGpcVgBNoCK2mfw2mG1aW+dxbhV+rhW3EodihC92ED0csR6QxShAQ7b03IevS5X5lCEgoY5Y+YANkQtnxe93AKWNnRDS8tvBHFpVqP7EhwrQ2zeoL7VwDAbmipRUZ+tq1C1NLyupiUrKidFCIvkFWCRqUE+qU0YiyMttrB7PaZaGuGMqmEl1beRyKMJuaLkrHI6eyLpbX3p0C1N/eydvJXSV+WzALdET1WqEuKASqfdTgeCYeW0GDEE3+0b1lFZ0rqSg7L9393TBROIsExGQdsN92blqkpQR10JjeNdKqx0OTXOSh/pfaau0g6PuMJsg0kchRMjXNM+8TTWpcAABSd0Csv3FejALsCLgwVmGggoNImf0TV+hzC7guaQYD3SmmZKXpPu+80LGlnV04CeiuabNb4mUy34RzAqaPBnUANOASa+HmJyWhqYUmvZO7rj7TcY84pN0CpAlNKXKNlQR27lONxb7I9nlY/HxuolVe4G93ywtVw0v7JrU0ezFl9BgTjm4jO8xDEYn480jskEVPUIRuPzE8Qxm0Bn5wiGExa0nmI6AcE5gvH4SjHFMR/f3sYxIIJ81/CKgLE/glv4XBNx/MJ3nHE8wOdgiKPrPldwHMX2uYLjaHGgfV4EPfa5muJosi9lNo7a+lJm4yhuwBYbQXRdW2wBNqWeBkv3gNPN17HFXm9V/Wrm0WcZOU3n3ehKC27FjYK61wvg0qTuMKSooOvBiskawsfAI/bfZ7oraehIiPG0JBaxxnaYNKCyoXlVQ7RnQTkEtrmsUdr8grdUsF3oXMEuG60tYl+hfGMEMobWWEXvSujI7eZY1xgSCDaMgqb+t4EyaJiTWmBYrRX3+2VCa4slp52eipjr7yrkhRN31FBfdUnTwbBIE8YKYjRKTUuM1ZQrNYDq/WhjzGtuK5EAnm9jvuaCBWprRlwaX6OJuIvgCxmJQ25HAohG7UAd2gjE/loSwDUI7lMK4pA8UEMrAn1dW3F0uUVv+EZBk35ap3N0b5eE8Dr44x4TqmfxdA6YPfmrjS1g2uloYI0VaViQSubWYp8vtV/zanebMFYd83qxVFLtb5PRgZZbAB2rqRWElP1qaAnbxkkj7tE8idXC3AKxLYSPF/g2KLCF2m9LGwlWNNGgdwbW9KUlhIPbXesg8MOKW+iooG56lnU0pAGFxooavwu3xSUqAK1T5Lm0U9GvcONihY4Cdq2j9YRr3G6SPRolBmKpiRIIb0Wbu4bqbVUgshZAWBusU+fcz94pT9JDTE6LvQuvl5kLCoYV+AorZk7niPVO5FFJaVtvFCwanI0913vaNbCwyuXVVKm1mu80EJbThsWX6Hse0LIjrrojS0Tfdp9CFnfdA61DI+67baiJvsiBrKOIu+zLdIq7n77cobg754iG0fcuEPIQcfc8hdjiLhUZeM1t8fVkjbswbluc6EoHX6eGZkMRvoEtLWhkcukt6dzTSmQtCJU1LekcLSUMdL2FpkY9xAL2UOmlgOdXEIWMZUwxb6EEnawEIxMmz2GGSK2fH13cdNC2G6o41cDfzUOw5HVc1NmQ79s7fZs7GpdRE5tBB9lahdPauAVpuXn59aovXoNhgYrBEUjmI1Fx6OPTduIQw6eDxh25L20h7jDdoKXo0jFf3F/za3SUtJSGiPx+d9otLNGKfGvhphe+bgY1UNiaRupg4NKLX0mUfkt1osKJLW3MQPVGd6+iZ+0rRB037YBRJGLe3k6YcRWV3KDNClgcdnuvwLeiS2tZxXc6mopvZVwOVgvHVFjQ7E+r1U3jRJV11LLVgS8Iq8HVVmunL74012yPzyEctzs+KTpuh3x+wLhd8vUMfhZxuKJsjb+9PJr8emqmHWbtRBO1TmedgqbXK1U11Bj1mnf7nMpx73f3CkXRnmZ4VLRGk2Nhq2lxOctrOzQmcjqeFzSU2EpJqUy5VScdqASOZHXOKow1L7TD18w4IINEzDqQixIxc9f6GRuf5DEgVhBs7daWaKl4fXXMWeuUMaoBiPRBe24q3fNSwCxHKspPNU2UCBtBo7fOVviemQv2/Hyla1brOn+tnPPGivk2V8Kfp2IVQahpXjDGqV2HXahlYAOUmor/jVZlGuxT4lStxrTR3qFDHahNHQ1QMBaUUsfaYSnnCsodeAqBPLvH9jM6entzdOIOx+7FGL2PPuoYt5d2dNsz+3I/qxe4QfzYWtF+lndt/7SSmsYamo/eYKmXr9EGraamfjS1YQ+S7oubp1WOTtJQp4/JCWl8Xv0GZDhMCy+o/7e3XA8VrSyGqg/G2zaW1G0FOFQ0vtT4H8xM+diXTgKzW4KYYKs7uAKJDgW51pFLrfMogPNXcGlLiOzsLFtcT3t4V2B4LAELaqswc0u7Upbgjm5peILVpg8LJveAsWgbVTXJAimhz2wnds2N+opNwaJv1tdqJ3bNDfPZ9ePul8/RH3fFAgpmxC0Lp3o/dcV8AlDc/fJVZYq7Y4GOHBHXzPfOuJsWsMVE3DbXJxBbPtvP7wraghhDgisU9BzO1QIeosRnin0Y2zInDy/99CHu7YFbHjGDUMUQ9Aj0VGszhvGvIR08s5Xr9W0gn9/tswUMQ0JbOFFLTiHnipaBqmmRZXXpXn49zvD85pbParv3hW0Ur9lYr+HG2lIrbaP3p1O7ob4t5aEVFga+Vn2rnAp7JayvR5coyBEtNeuV4Hs2oRxWLZqalvPsQeVtwfBcOojcY1sC6kI0r2sDkjg2q7TcJHWw89g1G26HX0bvja82VNz+BHhUxB6FZaun9slNBY7uMPDFbqih3jpywRq8ZlgJsKJh/ij39dRLV2H9Y5LM2NFil1imB++ESwifZQWH4n1xCwyUdo1YpHuMscV6PTalikZxdLRjYuXjTM9uTV7T2ubeflU9rfYslTrX2hI97a/VEvmaubsm5eiy4K5JGU00Dc12w4aITlOMZ/pHBv25pWJgRwtGDG3KfFrmNfP+Cm4V0EriZu0tdxPXuzzU0s117Va0Nm/lWIwKeHNJ2wD0nkyYK6Tkl5Rf17TAClZOLf2V2aLSuMK1vyM2w6fox21IgOlGLNKlnNHNv0I+y4Zm79RgVi18hkJLuMXMSUT33rJPY1NCt9TkUMPluSWVrPjHiibUmrMsnyebYrhSTzUKu8o1RQVkhZjb2YOk3NFAtZ72QcWa6Q10UkNsw3iz3lKsnOIVWAATp9cgOaVIUVIPYkFtPD0tWFHQiNuKGkd60EhDruwIlPTVW49Dy7Bt5SnM9BW/icM5u01ANHrY8brR5x7IH484+0AWeMSpeqOt4oIj/8F5oj1YvjCWoYFy+z1tlfaMPFF0SVplz4YWGI6PowYvVk8L4LVgGaFtLK/uZFpDKE5Pe0QXVN8rvuwtHS0j0IGTvMYIBycjqQZWbL2sDeQxtTSfrQT5oqTK4JWJVl8rMfIavPNZ5uMwyhcXHodPvgDROBzx2fTjzt2XEhZ39s7I6PMPxb9HtEVz7QjPK4yKJRFq2s2kADpju/lrcDs01JGBuau9z3Xa0vKbGCVRgYbXO1exolp94yRjFMFigV9UTDV6j3yieNw2+fwlcZvkw9u4jfLWU4hr7OYWtPtv7eDYwL/KqTFYQHyu7VEuqeMIHTEVHqDV6rejhfJQKSqQ/AS09ud357hmpYGOAxGL9RXzjluvizPRXaVdO35LK4xW1NBhRNqnUpyjH+M6y6Lb/7r2vo56XdEoXYGAW2tFL9rfMVDYBozHPb2XQ5lbu/RGVDSszxIYvSAflYubqjfUOa6UxFfxVj631OV/tx7wj8qYf1YJRSi+jcAt7cJd+ZITKhp8h3G2mJvqBje2NMi+oa1lhkp01M+FbTg6WhSYyE9BP9cz3bbPL3P3bAn+H1zs4AsLql2DPT5bdBwG+XprxWFRoFxYBCa5FK2y2lLRUNt2rNx7ReXRDqxGaE/tnUSeaylHAdjeOq+rgex34fLt0bP9WsX1rpm1t71FAQov1m8hpQSD8QbG0VmAsITlxzqnWgJmLWObIqylWvrqTXVU1u/AX4CMsh1PF4mety/bPG7uzglFz9y10kWbed2bUzjlDmsn+7x0eh211BNjealbn02ohLW1IOpia8/OVMGwWy13UM3EKsPTgGzYjRzrNYsNGCYiFhzo2ROx6EAVxIg1e3N7o5pM+ztnlJRvN7SGV2GytMCi09JNrGhB2B4aDnfU7t1SplJB8gkiHNbnqh27mVGG+/Hzj16bLTFET9oXWxY3ca+EH9fK2dtVAtu6YvmJHk06VgcDLLtWU6sb2vGqp0Ijol/vq6kWNwNvWFxU8US/qwJDlgo4WwymKaF8DjZVbGnclXlhAS7w/5s88vkLEiOuU9ioUHBNi2N0lFRwPhVgZm910cS+PtgCHp11FWRPmyJM0SXuBqLeQX1r1P6xChCsoqKB6o3T79F0I65efpGajxnLuNaCbmMNYvEQN4ZtQUvae6QdujLTYZitgIYarC/SudZJLDzWOJejHsrm05I1tROtha8yBqniuSaMHsS9gvqgeyxk/azq/wW9+DVFJBRJui/oLtDT5L+Wpk0WULIXCw1brWE7GqpYgKLWAlku6BEO8vrzQkNQtW1p7S7snFjTe4iBuD2NrnXpcgWuhD5QxmEI0frHZ2h9g02Na5oY09P6rbW2zGKCegUBMKUTDlH63a9xLNfOtf6/qWNPpY49MzHq+eatazisr69cHNf0mZri+OHXsjlew+V8DTLiGJ0PE+J4ne8849idL687juPZmlI0K/PZP+KYlK9ITRz78dnT4hiLnZ4RzQN8Tdzj+MD/0hRC2uY+giPoDcKeiFFJYB51zModKR35tfPlBfW0FUvj1GHrSGdrlyVFv9ZXxSPu1d4AuxJihwraIcRk7vo64dVOOQTMXh1uMPFzxlZIegmyXQnOSSxkg5Ki6cCJFUsrGkJUWrWMIIcC6yH2ToQuLUdY0mtd0+7WNQSA9S898QXR2+ajM3Fb4bv0cYsEBPkveaVI58PO6Rve0/CWThk4Jmy7dpvbx/0b9shEfXi12t4/bndvV/fb9ePhuD/vb/f3j283x9N2v2NwU4Q7bU7868f19nS737Gvz5s1g0kRZrd/PGyOD1sJ+Wp/fLx9vVmdt7s7BjlDyPv93ZY9a/P2cXV7u7/szvy5q5t78cyMzo9B8HezHx8vp82RAeQIcNyo+bAlbE6b3e2GzePM3n7Z8YfN/bB62ef9mw1f60KB3W52581RvMj/vKUCPG7utqczQvE3iPknE3zn7f2WPRNefdz8Qe9eQo7i5t1hxRa6u2OzerxbPWzYph/fihUn5CzYTNiLH1ZbNtfdir2bQ6R0oeHZkYO4u6yOK/aYjTmIATDz4cnN6pbt2PpRrUZiSpL7QMUmXrbiWeQY9KtwX5OF7xGwC4/yQUsf2HZPgKYTL4bzmZ8ZIN89DkU2/3a1M9ORr13fPJ5er47igWT7V/fHzWr9jj2Y7cb5fM+3f0q2X34t1rf5jh0EB5j5d1MAylmT/T5sb9/onw0aTHP6FnkUu8352/2R3+wpxfb95bx5fGCXZ3W3eTyvjncbuudTsufqMfZ+ybktKXb982VzOjMc2N+v99/uhtv07sA3I52MQp+3DwIqGb+abzbvOBTd+sv5NTsqRlbIQtLUt7kDipqJ6UNgZ6tA2SVh0IwgrcSDyBmwB7ALdj6xvbsT79sfNjtJ9nLrQTt2XDuONZfDenUW7yJnQRD5JB7Gb7rAnXThfSl9IcX7vSYruAszsu03R7ak2xWjAmuGsXyDT4f97gSUYJZ44TkBGmAswrPlEPCzd+NPm9Xx9jU/QIZQAowg/+v9+fTt6sBu1/7Ap3W5t9ZBL8Lbg944ApT7KIq+mvrWzeiFWO3e8NWdOBm43R/55s8WPog7hFiGIPjfnF9Z5GZ7fry5bO85jb7dPzysdusTh0p8jzluHvZv+VsyvdF8kduHw/3mgbOi9eO7DV9I5t1ojb4cYIy+XHb3e0ZO1C3IMgt59WTUJchyLysxVCib+6jh6fXlzK83ByB7qn94PJ3ZzWAiwWp3B1iYLX0Hud6s2M19u5J8Mic7vFux26GoCv+RbOzqyFiiZD02MuRTF5DT8P1erl5BpS6UOBMXcuZ7nkN7JB3LMxdY3eHtju2MljPMZPMgvLOuuQuqrhX735lhMRMo9o/3ki7lCxdaC3dkAuRc1pv7DTu844bJaWpF80l4+RxXtmxFitTPEyM1KV7wenP75nR5YELMmf0tBLWpfevlIwWEEIrYsxhHEwIWefUf9pfjbvMO+fLhfvVOip3JJPHBmokygW91ZPRUSheTqQ9YHT8+NB176IHPnDM8hskCejY6hfPm/n7F5DlGCo7vtMA0ycbGnNnHx93l4UZKh5P8SeDD69VJyImTuQ+WI4qWwQXUIghlUPz1nh+xmu5ybAaMHaw4/uoNSSYR0PLBiff4xJJOljiTJNOxx3J5WW6DJoRJMnqMx823TPx7ZFfzNVNlzJiZf2cQlqP59qhEfP9BnjcPw4LXa9ibPLjzm7ccre6YXHeQ8uEgqyfeU4Uly7Hry+GesXCtfXgPWUIqIeV42e0UzifeIxbzUEN2am7DtKaT0H3a7PaXu9diHwTg6C09CyFTPtF7xoyJKr3pxAWts+RDydR7vrvNd2eJQUxUWxGil0y9p6vYKNyPqfdUz0e24XwiCOk9z8uO/z4MUIubjz5Vb8c92+97Ab8Y3TXr4d7zE1ur8RVORqiUk5HNIOJpkiZR+MekSyaKwrAAveX4zsUNI8GYA0rTwPUIgM/GbzgdJjcqzcbHSBbGJFtJfB1dQI9Q4lRiNAEbwIPeRhcIwtJDNXpBCJ6szGgITz6dazxqTBIYc8u4rZAoEqMk+EG42iAOw2gLNpy4jFJkEXCz0PMkywHILAB5t327uRwESOh4NpJpzLx37vXluFZIDpaTxQgo/04AhTghw3/O36UwsT1v2Yb/izK02Mcy0BFGoASEfQiaIunfp/7fX29P4qUaFbN0HM5or0k2G6ezb7enLVdPNKnNsickIkaXz/LCZLkziRMsZT4qLF0Oh/1RmOi4niVRNPOey6vtd4+rb1dbDrzd3d5f1oqRZcsQ+PB0w47zUVGFKTNHpqjwAWzf7sT5GqksT54aykWA9eY7ARymhGf2VKkVMW2RIYZEGqOnWHh43Nyu7m8vXNoH1M3hShl5WcpZHDeIzp8YXUVDMv3kYctAuaCi58/+exGYYjQVc0v32x3y+AFyHniuF3hhAR/25w3jJuzhZ/+ApbtEyXVu7/do90iM5mIefdy8ZTz71ast27izvKO395uVEuGM+kLgjepgQ08taJis0EsN+56nUaqJFKqUHXVmPdwRDgxGzb322+GQduutNt/OR/WH0+rtRmsnp3tBvvQrQpwNhgg4amgc9gMQ4Tyc5Hw5NnMpOkub8WQMUMnkmmFrAX4RYmjcDGJ2XUBOxyA1V1ukI1ACwGZn0oApzSGa7C289PPE1O7bsxAV1WrYKCZwP6zE/i/Gz+0iPSeD/TNZeImrJEX8WN5tuNrKeNVRLs1LWIVhTM9n83A4izNehCQRAj4wmGVANXDXLKCTsKqi9X5xzSW0fXDsJ2nECvDFpXUTqQjF8F1wPbWJSy9rXF3O3EAgtnH1lv2iFYBlFtKBFNEgOLfMAw/fC/sDULHlfBzStVos49SF44rRhcezmf8yLEBxcL2XRh6cTkJipiIiesR2d5KINp14KSxoGgN9nU6mozLfgDRTv5UGyI/kp49soSduUTzu7+8N55+OW21eHbfc94K2itSsW5Czwb6zOg+ekcQHoilfatYmfnZFxXRiWSfl27XDTU1jNgLDiOfhXpiU00nmgYPd2e3fcpvNUc4sH3uxJIXpxOYHIGKI3xcjD9FcJaW2JAUlCYdk/8J5NBl5lOawaZIEJmQApiOPYYdwZNx3tZbuqtT/LAvKu/nK42PEy/0rc93EoMw/yNjWgwNz/5zMXUyTwJGsN4yN6HNJFiNAl4O6pWliU4I77ubQAqRw1vFTkd8Kb5htqk6pnUdCislyLqXURfZ0xRVTau2R4PqZf9grUTilZh71erbfADFzIRRGCZHMvC9z4azbRe051grUMwVrF8BzD7CQRhkpZGoCbMzCu7cCWPy+dJ/0sBI8bb+7Z3Rf++JTarVRkPJtry73AutTzynwzRpYaJpOvfMRUIPvJU1T37S+M0IX00Y2jCwbqpqms/ET1SPVLLIwNDuXrQbLg4jpznjuhVUODgfafyyDlzddjgA8rve7lT6X2WR8q8wWzTyno4Eci2U6mwaPm7jIZ56T4qE1hzON2xGwsyCysffK12Zj2ygnIOA814Ub7gXBHLiSCE4Q8PMYeMMwqUnGBufby+7iq1ewucvwDTdEPPMc1c1q55muY5gZME/87L9FBybvcT1TR0JkaeA+KkABEz6Th+3dUdIfzwSzK4ap/dPUK/NfK3u4AJ37kVte0mH7s4V3+7eaELM178+v2R/iJzFiGRzhXoZ8Ej5dfReVsJZ7bpkBWbPvtNHlfvsgUT6fhh8+KKVp7jlMFXyj7uX9/u6Oif37CxMJ9uyT5J35LLhQ7dfA2y2G+C8hR9V7vSO5H5VVKF2a+w5ORfBJW4taogD2nJ4w7RkGmvtkt0EamXvOZ33Z3W2U83nLvXqrk8SpeTIOzDUboSYy4rXdiwnO/fdNjzocRUiBuZ7zdBTchOIY+Fl4RtoDqLiTYnxyWPbkMILF8/xJeGNYHZY+Dw+ynAGbV6+Yhi0GLcKDCLBZ10XJB/NleKQwzdoDFpOxRZkgIO2SEUOS0eNxjNbpYvz41fU7XR4eVoPyny7S8MzkFcBD0t6x1DHreA8KJufBAhV1yJmqcJ+SJww3YZEHh0q2FB45ghXc6Xdwz2kx+i5re7ihQZMSxwKkrj8Phljdw04sJ6OAQtcXcImHmCig8369eieC3uyHSfuRDBV82Jxf79eaGM5oLAiGMj/ecL/wtzIwWYBOx+OV+aYJuNSFG2Dut8IEOJs8Ef1sKOSMKuUupBIsIb5Ikd4Z1dDdkYYPbkRojhk2jxtmPstlL+JG8YhmHQRI9Xo55tX2uBHuH3ugDsyeUUU/MOotI4OvBDrQeJEAuD68ZBoBPJxN4g3CE4im7Dszqv6bZwnZhoQvUpX/9nIUIUOItEz/1+PFgNz7ZBzhRD86yr+0uOEgAbZwYmw54uprzybPrj3XPtSWiDFLZ4yaBbKyGQ0AMbM+HPdvt2t7T6bJFQiiHyEGToMHM6xy6g8SljF1jJCdX+2PDwLQJuxKqbGflwXAdCwqAxdw+TgcDw0WcOQiSrOEgJRv81w4JoavHuzABAG8DBOl4aqkNuXEp2pwxSRnqWNJOzPZaC3iFg1ln6XTK05wuz6Ye2PsCAP27Y+CIgPOUdvBAImBf8f9HRMhTgI884MzBvFK/J77f0fDrZzcPHA/9mseanJQoV6zdDECN4jRs3Q5AgcG2AfuOOHxsiLDY0YNCO7yxaUDBKV2BBdeKloAP/XDmxyS4ZypMWEA5e52le4zCxzWerPbyu1yTAjCXnNzv7p9oxk2tR6YnzgBPwkRdW0i7wX4fBScMfzz5XjD44+M5jqjFgRnzOr2LF7zwGihJDbUguAdcNmxTd3eisDsGTUmOPDs+ktHy4xGiDuAZ2HSuF2dBFXJpuOzWHMf3layDmpecGFvOIVXyo6An43CM7GGiyA8iotty1Em1Yh4XzE4i3gZu6a36pZm40fMobf395s7JvOJy70SNDobP2l2Ke/3Ig5f4GL29BmvbnaM/HMxlWfLiEH0nLfH82smcg7hpGy/xElQm4MDp8RUam4wUMbCL6w1M2piYPfCAA53j9oXEEYrRJJtCNjZU7BSWhawTlrAhsdloYtPM4M8fxLUSE0ZDdZWWqWI+BJ64k7apDMqmwsv6lY7lrKJl8Gf3vBoQu03yqgorkwu0mqfUQF8t1fE0tjJMip3v2aSBf6Ye5Yg3678aUDeMypR60mK/KdHnSFB5WfyRLF0nvwgd285CnjkeRIiu2QyCrfZMelGXNDMSjq8vHr1eNreb3bq16n76/ki5kzFX/nT/WZzEL/NnN9Wd3fHvfgtc35T8bFy+nKaAtK3z8K9IcjATuVMCbVTwM898DqTlD9Wzs231+biaaDAPh+8kZTZdBICP20fePCVyIA1OS5UslXgr7a7rSDmGZVf1c/KnS0sXSpFKH0CjGvjWmrJqM9LQYuE3MftAxMtzjJviLq84KGDIz2b5v6wQaWMAuDcd08VZaUb6M33FBRBeB3NrXZTD0WkMsQG8GXLbXYTD23YIY4gS5NAUBIJ0sqoSCvBzkx+uBHhl++4R/bbzUbkgaW+8zmvbh5fr7gDmKRrpd7T0QZH34BsbIAvIyz13abXe0jh4JK+gJw/Bcm2bS3M8+pU0kXkCGVmyNJlEBuVl0aQsZnvXjFN+PZy5lEymyHjNpslflBxzB5w3x1TYfgCKxjBWgnbT2akW2X7fL1VGUv8TERKpUiDMxIugK23mGudzXyH5oTgSZpo6Iz4IIfnweHn0PDha/UM39meDqtvd0T5zma+E9WxoZparvc7uZleaqmCzZQbf9iFzHeo4taaZFilOAzUK/OeLmY0DaDTIGrx/EtFiAVkOjoRvUp3Mr7LupaRn695qKMIlbm5HE9nI7JkmTcj3MAJAqMC+bIsDwELtk0tz1k2H3/07S1MfTGyj/Z0xIBl3ADDtHPf6YowtPXWlHTIEy8Wbjbr6XcEzneWe6bL3K8CnDhPR+arR2oTQpbPxqCPN1tuW1Yim3x8Fj1gCK3K8jx+lErKzefRQ8xZ5YvrxjzyOGKZcZXly4ixwhSkZzifRIyQkuuw4fMkUBhB3Bvfjs+n4cu2uhUsnY4Tg9IRGS/8Kh82UECS5pTNsycHcDGf0ycBnoeqQkhJQ4/UUW3ZfP7UMm7Y32+MUsEriexlTvaCpuvevgkgAk/fP27kgS7jx9wp22JG/Xjjg3aHWzEkiR/CE9XFmKkzZuxgnCBsz4hBJV3MnobWF0bA26qxhUyK5C/yUTCdXr8Yu+knJkwCvaLeOMcnQyzS2WI5Bkxt5hmNvz5dDjxj/sj0Ao1imoMsbcuvMZ+ZFTnx1gOIsVtkyzSefAzJPflkElQUFIA9P/GbmlruRAuLXw0q5JM0rIdI0TWfzIIgmhLnk8w7CYVDa/2yPPgkasvIJ/MnIIc3L3xvpjhs3r8MPxWjWPNk4n2ogYFnUnOCPBetAvDIGYVOw6O9B4Kg8Ozw4QzPmznvdwokUAuEhQHU6HB6t7t9fdxLpYQnu+irmDvONA0qwDS+OaG0BIoTLAG19L3T0ABMssmpqYE8zpTUUbkbAjwZm8Cwt9TmQIF2J/Ws9OlXDwEvetDMN4jcB17gZC9reokR2dMjdBRWPs2fABYTsd8wDy6EWmBzapcgj7chl0HEZ1PYi8JcA5qm3hs1AA4Hk3rp2avV2/3RudDpNAjL5LzT46v71R2Cp86UhxmAXGKIS+o9S4DUXw0jsjHMHsDyAJbKFW522uuVO/G6Yto6DIJreQJqETwMRgqVLpw7wbqaVgKfymdehiNo3+3r1f39Zncn4VzCd3PPcG7/IIQYGVOidH0BPw3CKzOEUh3zWRqEtBTxfDYLgkIRinzmZU/m9Xrtc4vZYpEKsYNzaqUnAKfLjVYV5pa9HsE0PZ1bnJfDAGINYDMH7LJ7s+Okhx3+/fDKLPhKFYplIG3cE8CKgM+dHBb5ytNmjfu08AFJmwNAaXSzZsNLPg0LNLw2WBNkjmksCvOVTVVpc/PE3XBpMh9quUm31jxJvZAqagoBZ17A42q3ZjiDgFlgxwiQnSWsnnOz/06K8jfn1Xancs7myTwMrRw7VrylSm2YJ4trR+oMxrm/tqCymPMlHSRrgXzcub/UoByjAtZ8oxJLUD9eNg6NnFtVByUUXJHN/erA0fJ0WO0EfOqBf7U6mRVLY9PciW9xQQVY5gcDiPzJB5lrNZ37YUHNmjs5MBpGP2MZLKWDabHzdDRnf7Cvzv1VS6T3it0/ZTacp96MwxsFad96f4USfblVFQgp7+5lQbV56l6144Zn5d5tXLqZZmFgkksiceWfLyu5CC/V0yMFxJx6OgyBsXZ3EcILKRjN06UPu5G4XYYaTPPZJEjfFQrp0goC2uU/yvpu0lc33wlkcoqSqPWej1uGcoPfe+5UJaGAit4yKmLw0KlP4hshADNT1G/YTA0nH6VPRdfgu9nrSGOZvQbxT/PZPFC4Tw6SFMZMcjEKzJ8uwLzVDSWMiMdRWvDcKVJCYVVkoYFOwo+1qoXOqf2ewg653avtw2YNxMcpZUIHatzh4wR44Mxu97vb7T3iQ5aNQ3oQIstjhghIcsdU3Swt+mD2w4KKYlaROBVCKOVMAe1ofXSAmunCMYdYcKqIiIriECPS8REm2GQxmT01B16yjGkkAjgbB9Y6zDCAxsBvzkPet7BIGHfTwoq/8O6cKqHMKMbD5cHQ1oXfmIK5sovJMggiM2WHwq4LvxkFYVWg2yIJm0iJO3yRTIOAxGywoHIeAZQalGCBCyrlETDL57ugVhS5CmFK0aVvSHW5BbWrCHA5w5MW1hY0fmOtPKwi7FE8WRtwFjSE48QIKK94cjKy28IyqCgAs5DdnYjVWli2FApmivkIyMQDyd3yNzwQcP2ogtoXlhllgPv2NcdeJpsJNXZhmVIoUpqiAjzJS8t/i+kT98lQlYUjqnHZW5TLAZh8ZALGOGXL0wtHbguNFMCLiEUqxJsuI2DFIniY4MKxn1gjRDKLAHyCEqpY0UU6fZpKiIdKbE7Tp8FN8QpTcmNhGVBihqnyoWJ0FpLIiEN4kebje6mETn2m6XycNKzWf7gMBXMWacyp8jAXM2DsaI3axfdWbe5sjNfJNCVRMVrWDuZV+P1eAYnzAr+WEyualpf4YPrYGTWO5cTqcaCeMNgpST6tuZpLartwx3HrsbJkfXe72cgJzeLeddzfG+l4Sa0a4UGDP2RJGaW/apaAs9jk6qx2yTafL2mwIptECM5mjbqwisjuM6RomXgPT6RjXXawy4m3U4VyEcmFac69pHzxgJFIkuAsnfodAkix9SXlg2S8kmmXjp1DQJ1kHcGlU4pD/KrSQAXA3HnDkDuwpBxO/Lo6M7Xr9cNGLXA5UhXdHAFlcBzquN8/WDCJF8bEeEgCuZxOvWBO+Y0lZW3knSsVXSPAZkEwEThm0pqXU2/lMoxFWFJu5kyOS9KMMQnIuRcSUhpVPshy6oumEMCqoD10JlDsfzldhsYYnr6959nyeuLpJDRgt9ehSKfD5nb7SmZJLNMkPOAsKvurUWLlYsQ0FJvn3NjUf3SKUSzT2SimQHLfUrIqmS22fnx0B9lxt4ykntUK/WepN0PJjFrUW6bz0Ulpv/WSsi0Op3Ss9XH16gxwzsUCLLJgZ871GtLRNiKtXgjEmijNnJsmn+fMdTb1A7KnksITw5OpdC+AlTC+e7zR6qzcX+ojoA8mIvvS7bwgoRnk9vR6Q9gMjU1UT+XFoM0jtT9jSUMQYbIczx73IuVMsOPZwv/+/eGw33FV2TPlZcQQu8TUMvOLDxyXLkJ1W2aBozNKkf3E6fhRKy831HlZZukoZdoA7cxmAfwQVcC38nQEYDaOSBq1+UA1IvePGIvRWmbOHVRmco2nq916qxKV9WoXnqvDVSS4bXz9Anbph+VmROkt2N1vhQNsmU8Ct1yMUGEqitrlSWAKwIe9AYiG3JouULn/7ETRFt0mgg6YhQfwMjDaFrzMsxCJ2T4MFVs0O7HaRHAvqhjj6fazzOeBreJ4JgsuqoI0yzxEO419amlV+jBvZudyv+LseivXY7WJEHCr7SNJXZVIRUMFKaSJd9/f6zk6tT6GOQjDpUnfWdLgwMNx/2p7b3X1opGAzj46BHueBV+udQV+1weZd54HB+iqJAA89wGblfG2VJtBLp0vRqH14w34MgSuq5fRxy8m/q2RrrRbxf8XSQgdlPS21d25ljS0bwDFtjxLWpTD2d3j5hVTK16bMBQxJHCGgkiqccZKuKTlOAZojnESljw7H1/eevNqw5srcWVawM/98Co2frCvLheLIGKo80Dg5TjOA6hbZIOCSq8kDgicIJNLEWo6vhGmKIs862XgGI/c9A3eLVPSfbmcjY+wIiCWyyzuDfpkaIFVUclX07eNDMO4ecfL3wvYuRfWtKQ58JQ+PaHVei0xa7nwjlLmzbOKH1ou3fgh2n5hQo0c9PV2soIckIwMgDQLCTz1AnMQs0IJmHoBhUbhFLZg4LMQAxM14/emJ+BkMhZbL9ijgcw9vfoeVm82okSASfJhgP4Tc6kQA/U5yODeSaCl93nqGktlaej7mExCuOgUeWLAgft2vxJWBZGZbI3wn5j/6f5Dk6Y9blMwtY8nSeDGeWG9NhB4bT66/2pZ6gQSj14ApQutVqMMnjbKk2eg0+y4lCBqkUnQpftoTPFjt+0kGz5NXEDL8MOA9FHx1T5wk8H+wtNyBI83FbAnU6cLw+X+jdwhu+D0ZJoGYQeYWRBGWZ0YDLlDm4c9Z+DSEURVRgaau6DA4xjA3AUgIhoDsS+NhPrny1a7d4bZL58CHe5ZMvG0wFgP1dGtLl5nUgxSGMRNeyZK1jyQ0IUqdUExtvFyONy/k5DeWtAM3c7vPCbYJNC9i8LTUvqBHl50CK9QowtXJIFOXnIE5+1iQqKWn2rg5G/qJQfoCkTuoGV4kG6vYe5/oLMXhSaEKtDgS62C+guTQIcvuklO5HYS6PMlh52P71RLExWYd1q93YqcmiTQ60uO26n4Yd7m2NRnlqOyyG1mK8OdTkYwQJR/NI5W4hxNAs2/5EDTHWRzf5BZjuSVlKIKHZ6LvvIuyIASXeEAmo1R6iqHDa2DzIaqVo8n9GomVk8wa7AaIv0b8EZ/fzB1uzHUOwl0CJOgqsa7PSLYlwgGSciZO3dlp7S5lVsFX4jd+wMWbUumTuCGgMKi1Ilb8V73VTqp5tCT0AJstjMUtbc6lJr/G242pTRMHYzpc7tdMzRWJW4YbD4Ga5udGfw81D9X5lkD5CIIKf0rosGlBLUZzv5GuEiG1TvxGBrC1DhnMATTNIDJU9Kf1QOnPmB9Y4hcPKVESMOKVXDmBRVEGKw4pr0IlHt0n89O1B2S+R7PU/0gGpA0pphSgmOevpV9n7Wb2RozHxmD/YmmlLZoyAd2pXk7alNbbngyISoaTijvogQI0/ceeVStNlKxiz4ZmQvVpabTwLGq/s+4k1PvofKJqDobw5lO07Hzf7s5ioR4RnGFQiWHOLmHW1HHcYXX1K0tNwCZrhkMLB8DU/KfLoWgV+c9QFkBypQ7Vm5rdZLTxdiV0CdFxLApdYyd9yLNdfVOaBOH4xYzXhj9nYy9wC6QzuC9h3nLtJX9w/ZfzFnRhB02bBo1jB5xmgZohjMOiAh1nI2+yUyORlc9fZDUbQYDDCBt0Ti1wj6GASoRKFS/mI1cRIykfTSdVBv/KNlzcxK1W4qtQGzzcL1nXoxw6vYC2VW4lDpsWsabmOaNE28QggRS5onUYdD6GUPAY2K1bqHFd028iIScuZCbHV++CtJSvu3EauFCJ6fyf0yL1dTJeyFPliBzL8hpc69mtgi/T++FffBSSlLrXatuoRN3heTapZQNSwiFAFb8cJIm/u030UKJ27tFnd9OH4NcXjILL08fgFL9BwRKsuhBQzxZkiZ59DAT5pukyTw8ip8SzmvxBCiZzfIJYJjD1HN4Q5DZ5ruDaIxE4wgTq/NLYJRjtEin/rO1R0rYNACr6bLVB8Z+1DBXm/2eLwxgu7ofyILDeg3IwNdSfzksA6nc3klKGaz5HRy7SeqaUyTq8kIrioekTpCkruRvpu1ER2oImLWT7qJheIwfwqVUYHN7yCdWuxeEYQrHQQZZ6qyvxGr3oqGhUfphMJiklP/ZwKZOvgGf+8D5kqwZL3xwPh6XpsvQI0eYaTpzI1kFHr9FQ2s6S0ag4BBmVhjrAETnOktDcIHtnc1CA0YXl3kxWbtvpdB/y3N75U2b5aEtVM0nBuOP1RqG3KJH6Q9QMrbVFcZA2oKl0b3koGXUIK18yU7Rk2gibtiwjCx5M3ijRcFicgwSbjqG33yLdLvqdAyzpQCoqgMkVhsZG3jL7ySX0Tdr2iHU6iNjKCfpm5OkNJiEQg3yjYweeWNH32CPYKtRzHDYvMSindEniwsPj1+GJwFhyonVLYbIGMJmZcSs3L6Mqq/s5WYwLgztYTxAupeGYlQ0egTgvGQmn4UfPEjRKQ0cARiDlvK6K+g8/FAdITEszS8WqszWAWwxBjaoR1aXGALltLG1esZ4gcH0bnWNIeBGwhwuIy025X24/NIgzTx9YptVKSNi3R86x3i2Ww4YrIxWvxjM+B0GnfcHEyyRzKinWPem1Cnkul2s1f9CgdGcUQM6paAbthZVMZwR/LehUannBXKUZzYzD7BiERz64Z2KzE2srhiwPggeU1FeidUIQwGr+KUBaB4GGirpJ1ajC/1mw/qGXnWJ1d9CgfJUIM0hyYOTSXirDD2TJngJb9Mg6/iUajVzlCEFZ/L0kpmjDelliXZwEmTkbFTaCu8poKpbJ1Y7C/K8YVdlK0BzBFQDerjcn7eMltzchFxkM6r8+AbIT/quWo0tfAOAclgtLXzQKvVAR4ElQ3sLIyrDqEFKszpbqO2REs5gpGIfdFebZDYNHKMcpN2/VlMLAiN6x7ObytSfsyqmksymsycngvKc2+SCDOHPl2B58LF8qkM44sDWrH4XZMwgxLP5y7EnOWYRHCNgKYGZPnmgXAK8PHBqeidTNpPMn1n0anW7vd+eB9yy6pWb34klJ3MMQwaO1ruRdzxz/DgGXPPYzEmyNSBuQYUkc7JsDfStimZGYK9FQgJu1dvnYRCjs2d+K9GtCcIYbJKZay3iUOInx1lz5tfv9jTshUsSzSlpUFxf4i0ir0HNwSZWGXn6pEfRMVp+0jWpEqv8uTNGlaF1RmWjoyiKwLB8bB0D8jkFy/y7sghAkUlr4GVox9fb00GEmRF4hz4OYPoQp0kgGezAs59knohxhWb+Tj/mqQpNKVU0v1q4R2mhgTIh8kPjdKtI+vA65CID/k9zL7TdFk/Czr2wmquL5UvAhRfwvDq9AdyYPn1A7qOp+4Vsl8dKk6VJ9Dv0cDluOrrfFDaNf4exJlhF1YdSSm85iKZA0gMv4Z0obgIqYfLxSyqiRXwJlknuuBZsxcqtXakhVOgve7IpVJi4tSwtaB1lKoGddMfLkSm3p40TFJA7PEXVTDq93h8AKrNC+wwITjEfedQgEFn1LcWv0NhrfbnVLCe3kk85pIZwvNNWgUsCbJZvLktORXACPdxsVZA2yR1uIwfox+r2McMaKb8ha4RdkaBpGJSLYwc14VnoCNytSILHZW20hM5HF6eG4+LmY1NR4fnDZBYjaKGAJeAyuBE3l3cDjbWrYiIg2njccpiqxzFZntNJNLHLY3Lw0+XmdHuUtfXP+z0TKKW5MXf8Dgh+oGVwE7s+pg/1h9lnjjNtJVzGwk61k2TPKokpQPj8eBku+fvc+R1qXvDH6Ms2XTiQoGGTdy6Dz1Qd0NUj00kQkFj83LqXqvcoH2GIkOObkAar1f3qdqPbOiZWnUsEsVoHKfBZCFyCeYl7mo0PMkFPhnG6RS/dUV66T10XOEhlLMixJnQrd0p0uS/S1bqSnHox6H4aayS05U1yx4PhGXS7373ain6KiVUp03ccRmjNZ74DVtCS6eqan4lVJ9Nd4+CzHOpkPpy/g6LTa5MOMJTI5BDS8yYbjK+3653scKaflQcgIYgoN84KAApwOOOtAFAVhLk7rW5pKyEGvnTBeR4WrwWgc8/0dTH+CYDFxyp0g6ebvFcYwQ1thJoh/NSzsbQuOQNKAUh3rdwGV5jN3DnIUQopJFQWgrrZiD6WPHxbODPIs/PQKPaBTf5f6G54TpGL8Ywcrg7j78FDHYaQ9raPd/u9Mjvk2TICfsXfJMDzySg4tDNlsHikwoGiA7H8DpSc5sDivdptOJYNTZQYbDpCC4RzmmH7eX+7V4+eOZigcdfOsWTA2fgi6TXK8WQ5nNgtiWgGafK5BSSPwIbyHx6jaSduLRrgxg9NrwzMvvnccyMl2ohI8vVGtixkgHhq9h6R851PPZc8GHCHSDpPPZPZ8u4ueqRnjF3RSOTdSGjdek0C4ulJJU2VLDlt1/SRuXcbdfgDEYHncy/smWuCWp6TgHiGq520rCPB2e/u9kq/z+d4kKTXMUk2U+sUQxZeO+H99g00DmRQoSZjAlD3/WBwNtuDB6HwuPCmMg/pbaYvDgOdjYFub00eVk5TYW3IV0cZ7y1B81AqtagVICYgAeejgOKhEnAxCsjnKeGWPrj95cw7sDEp+ttbodzpUm9JThtc6AEG0pSRkMCJK0JzXLmXtZbPgkBsBX+QG0HzYK0BQ7rbbq2kW5oIa8HzzCiz0OVsBFJWoDPl5xh0FjEPLRasdncXWY+ZDcxHBqqSTYNEuZyPQPOAbHYQEnAxArg6bEVksbbATCeTUFXR42pr6mtOPYmtBsYuTDD1JLYSYG7XE1LzYXPc7tXz0+CQQWXfrrGI89RKdCWD7H4B0rEnR2XBUTQm1BqWj22UbqilTHrTyWQeAS6dSFN/JqwB1prC1JMMa4BUYqeMnpBPTUaPVqSGmuiFqZUNS0C1f8eK5ZXDpmMvwZESPPW64XkhowHZqJUFIEgu5HSSZAE4NVV9e6aTJA+/Fmc3f+LFSgFSRpCplRALA3xxxVMrKdbzfGMQUQaI6cQx4MMoA23403RiRXkOwLwukShrc3kHM5pOw49XRVmgV/R0Qg37bCMOeyyOtFaTmHmghhovUytpVgGAZV5BOeq6BJSF9VUwy3TiVMjcq4ouJKJv6qbOUjjLKjt182f3Ow/4sPduDu0Nuwh7qOUsoaxG1ByEIraVQktBDPJZ2bMUakBqK3UWp6Sqhk4Tx0vph8pDDzIUKnHIXgBs4XgXdo9v9+cNbNMyBAI7bsVwaIjBk853QWKTledqYN19pWZjB1CdEbUYO1AqR2pqpbA6cKpE1zRxEvt5beQ7kbmpt8ShYgbksj4I/4MSZ6dWRqqBoxuDkQbTxDERm1GATHaOmIKw9obahg2UiarDJ1KCNcx0vbZabEytxFKYnpCVBuPP1E39VFmfeivdrM+9ZSaeTieeyDQV7H0PbWlECNh/ffPi99/q339rfv+t/f236vffOvFPfsP+FeL7VvzB/pUv/uk/X4gp8soEwgOhPsjGqgdZsXSqvlyduQMkVZ/WGx6SNVOfjqLGFzeKy1TQzPf943r1IMXOHH8e2ubyyuieXzZvZVzpAn9j7+eyuDV8OQain5NMEEpVuQ0C6z3ZvR1cpdPhO/EMuXmp9S3ZxWRm/Sq3M8msr+W+JvnwtYrxITsjV5uQHTEzXtLN33NBgNcQfSP4Cf5oiumYnxOygeK8uHtTFKPlVa3fSDl0OgImaiBJfWeajsAduYwooGYjUKbP8jQbmxpk3k/zEUAmUax43juHm/vhJEJwgMUYAHuneMpyFOhhL7SRdDL+KIZYHCoZhRJ2ag42HQVjwtiei0lpYPOVX0IfeTobAxM1SMWVTrMxuNdMUhRzy8egNrvNg8jg5ZDzpyFlQlYaOAfRJpD/HjgCpe7K7iyKr84mo7Dc7obQgQOR/cLuV8JbOZuOAG0fDivhW52lI1AbaTjmYLOxNzLRVVz8WTYC9XYv2M/MdxJM8r1w5wy9zrP5E6BwpWeLJ2DNtZ4tn4AcWqhPnpoqXO8seQIYrng2DcOaa56lTwGpq57NngRU1z3Lnn6kvPJZ/iSkvvbZ/ElQffWzkUOyrn+2fAp0IAH55ClYTQby5ClIJAX5NA5akoN85Lw0SchHjopc3jx7AtBc4Dx/AnK4xPn8qbfri5wvnoBUlzn3ndJBFNH5VtMuIYTMJwFAbgIggOETEj22vARGtHXCX3gU3Rnklvks+CsXkGXM75zsuejedyeLo89z55ehcvqcSkAHboXjjUeFHDVfeH9Us1p6xVEjV05GpNVhTxZkx3b7XRjSt3uqte07uf0LHxKLipuiEYLnx7erB441J66ELPQOQr9m/nXufj0I3Yu559czjxUeQBbBB8DqyG4ejhtu4OLx8JJLiA4AoxDDo5ZkS29WxyMvzKeQYTn1/ajxQeg6TJXphaLTiP+yj6XQeAqt9FTiD/Z9p3WdGy5US7KTqI/GXKo+i2K8idJ1zBdT+cpKa0+tfkcp/ijFVFrxTS3+7vUrz3cqiFa9k31WsqP8oGVE9ZNkDDP5yRB/9RxF4HP5EfjyXI/WTH0hvzDseKmeoJluoqYG7DIxs4M6VmqSsouhVnM4kKyPJTalFPvS6x0xKmgnfmr1ry3onIefP3/4SW3I7V/e//LX7ecPf1V7cvfrxx9/WP/60799+Pmnm/efP//4YfPnP3/4/rN8mdFla3308kB68bJCowT/76DgbjEqQ30jWUsC2g/5YYrCL/klNXxuRr6fGc1Xf5MZZVd/kxslV38zN6qt/mZhNFn9zXJQW/VXqh632ZNe77VR9Hv9ZaM3ip+N3pOjQPyHrTxU+QXmek7lV9i4UG2EHHlWyxfDpLQlP0GrEbV6PkB16lCrV48w3y3kd7pVphq7pFPgorneB+trXbRNVXBIwhAHcX+SaRhit7kzm1rrfy1guDSgdNrC0gCinX79/vsPnz79+dcfNWq//9v77z9+/vv206tff/xRE5lf//zn1Y+/fHj/w99fv/+kdvX1zz/+cPP3P/z86y8/ffg7h1D7y/+8/O2H958//KD2ePP//frxb6tfP/98+sAeKaZa6BNu9VTlJPGuSOwo9FTf/MwmoGb5BzbLn9Tkbv/y8af3ak53P/78p/c/qomsPn18b2ig+dfpPaj1vZc3UOKcoYG7G3bYbzfQCDmBb6WJTd9A8aWph61vn/pW1CXVN099J5xIpt1aZv+ylq0vc3ghRKfo+6h/ud9vFYVcwNfoT9K3U/0k4xPXF0ZnJYnH9d5w68vxwmRNbZyrYXskSnX6kvYagH80O/fzL399r9Hp8B9/W3/484efPn3QN/T9T//OvtQ3k336+NO/Hd9//EFjz8+fPh1//fQXtS9IWQ3mtJpntkBIDEGtDTkxM7ocThCXqL/hDlV9hPzzersx3KEHRlBpo6QkUYVG1BJesfr84f1fNYtWf/MH7//06cMv//HhF8P+zd6V+pFSAuiBLyPVO/z6px8/fq9385eP/8HuldkIyThKMJSWWoSoNUAPssThKCvF6scdH2/ut0wC0tSj1dej0FdSTqjURy2/NNRD5W6yv0yWpjhjLTjzI94+PFyE9DITH6CAoSANSqTluK7kNqkSiSl1cEVLvawOGGllMBG4hChCKLupKrpqWcTll7rzWqpJ+Xn7Spk+1HOkjyFDUm/oidnrEmhVDzxMiRJ6XtufPn7WJPbXz5++//DTh0RTVyExqJnoH6eaZHz8/t9/ev/XD0zkYJdAU1SFVhf5UL55ig4r4vDq408fP/2Fgevp9noPWyPY6M1sNSK2arrigqisAFmpcTp8s1o/bLXwJ4VuBTMzX0gQfYA9Sph6Ip1+v6T3HZCP9Yf/2P5w+P/VXr36+MuHP7031OMkrpZG1wrYh/dveQPMGRxvRB7V0ZSiVd9td8qUDrR0qn5jgi9+naqvuQiM3880OBOG8ftMv1aE7MIPufpBCMj4w9ye6ONr7vOBK2+EJUOhDNlozB57qfHub98bifXDp8+uglDqnTPX3SB5C0Rpd1mdbfmUfzVoCeIj6Any50FTEJ9RVxBfSG1BL7XRGFoBFpVAnNTKzawGLeloHEE39xdG1dkjmVjz7x8+P3784ROHFxn///mC3ywG9O+7Nw8H+fv9nsfGSvH6+x/ff2LQL4z/SXOcSm+Kkal6PZuGvey//icHFzvxodQBAA=='
try {
    Add-Type -TypeDefinition $src -Language CSharp -ReferencedAssemblies 'System.Web.Extensions'
} catch { Fail ('해독기 준비에 실패했습니다: ' + $_.Exception.Message) }
$ms = New-Object IO.MemoryStream (, [Convert]::FromBase64String($schemaB64))
$gz = New-Object IO.Compression.GZipStream ($ms, [IO.Compression.CompressionMode]::Decompress)
$sr = New-Object IO.StreamReader ($gz, [Text.Encoding]::UTF8)
$schemaJson = $sr.ReadToEnd(); $sr.Close()

$work = Join-Path $env:TEMP 'ss_myinfo'
$etl = Join-Path $work 'cap.etl'
$pcapPath = $Pcap

try {
    if (-not $Pcap) {
        if (-not (Get-Command pktmon -ErrorAction SilentlyContinue)) { Fail 'Windows 내장 pktmon 을 찾을 수 없습니다(Windows 10 1809 이상 필요).' }
        New-Item -ItemType Directory -Force $work | Out-Null
        Get-ChildItem $work -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
        $pcapPath = Join-Path $work 'cap.pcapng'

        Say '=============================================================' 'Cyan'
        Say '  스타세이비어 내 정보 추출' 'Cyan'
        Say '=============================================================' 'Cyan'
        if (Get-Process StarSavior -ErrorAction SilentlyContinue) {
            Say ''
            Say '[주의] 스타세이비어가 이미 실행 중입니다. 로그인 정보는 "게임을 켤 때" 한 번만 오므로,' 'Yellow'
            Say '       게임을 완전히 종료한 뒤 아래 안내대로 다시 실행해야 합니다.' 'Yellow'
        }
        Pkt stop; Pkt filter remove; Pkt filter add SSGame -t TCP -p $Port
        Pkt start --capture --pkt-size 0 --file-name $etl
        Say ''
        Say '캡처를 시작했습니다. 이제 아래 순서대로 진행하세요.' 'Green'
        Say '  1) 스타세이비어를 실행하세요. (이미 켜져 있었다면 완전히 종료 후 다시 실행)'
        Say '  2) 로그인해서 메인 화면(로비)까지 들어가세요.'
        Say '  3) 로비에서 10초 정도 기다리세요. (자동으로 불러오는 정보를 다 받는 시간입니다)'
        Say '  4) 이 창으로 돌아와서 엔터(Enter)를 누르세요.'
        Say ''
        if ($auto) {
            $t0 = Get-Date
            while (-not (Test-Path $StopFile) -and ((Get-Date) - $t0).TotalMinutes -lt 15) { Start-Sleep -Milliseconds 500 }
        } else { [void](Read-Host '로비에 도착했으면 엔터를 누르세요') }
        Say '정리 중...'
        Pkt stop
        Pkt etl2pcap $etl --out $pcapPath
        Pkt filter remove
        if (-not (Test-Path $pcapPath)) { Fail '캡처 파일을 만들지 못했습니다.' }
    }

    Say '해독 중... (몇 초 걸립니다)'
    $units = 0; $info = ''
    $json = [SsMyInfo]::Run($pcapPath, $schemaJson, $BuildLabel, $Port, [ref]$units, [ref]$info)
    if (-not $json) {
        Fail ('로그인 정보를 찾지 못했습니다(' + $info + '). 게임을 "캡처를 시작한 뒤" 실행해 로비까지 들어갔는지 확인하고 다시 해 보세요.')
    }
    [IO.File]::WriteAllText($Out, $json, (New-Object Text.UTF8Encoding($false)))
    Say ''
    Say '=============================================================' 'Green'
    Say ('  완료: 구원자 {0}명의 정보를 저장했습니다.' -f $units) 'Green'
    Say ('  파일: ' + $Out) 'Green'
    Say '=============================================================' 'Green'
    Say '(캡처 파일은 로그인 정보가 들어 있어 자동으로 삭제했습니다.)'
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
            Say '사이트를 여는 중입니다... (내 구원자가 자동으로 채워집니다)' 'Cyan'
            Start-Process explorer.exe $url      # 관리자 창에서도 일반 권한 브라우저로 열도록 explorer 로 위임
        } else {
            Say '데이터가 커서 자동으로 열 수 없습니다. 사이트에서 [파일 선택] 으로 위 파일을 올려 주세요.' 'Yellow'
        }
    } else {
        Say '이 파일을 파티 네비게이터의 [내 정보 불러오기] 에서 선택하세요.'
    }
}
catch { Fail $_.Exception.Message }
finally {
    if (-not $Pcap) {
        Pkt stop; Pkt filter remove
        if (Test-Path $work) { Get-ChildItem $work -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue }
    }
}
Pause-End
