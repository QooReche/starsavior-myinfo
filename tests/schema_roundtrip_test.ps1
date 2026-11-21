$ErrorActionPreference = 'Stop'
# 캡처·계정 정보 없이 내장 해독기와 내장 스키마만 시험한다(캡처·권한 상승·브라우저 코드는 실행하지 않음).
# 1) 스키마대로 만든 합성 LOGIN_ACK(모든 목록·사전이 비어 있지 않음, 극단값)를 끝까지 해독하는지
# 2) 보고된 실패 경로(ack#3 > #5 > #1 > #2 List 원소 #1)의 바이트를 깨면 같은 형태의 실패와 목록 위치가 나오는지
# 3) TCP 재조립이 빈 구간·내용이 다른 중복 조각을 세는지
# 4) appmanifest 에서 게임 빌드 번호를 읽는지
$root = Join-Path $PSScriptRoot '..'
$text = Get-Content -Encoding utf8 (Join-Path $root 'myinfo.ps1') -Raw
$src = [regex]::Match($text, '(?s)\$src = @''\r?\n(.*?)\r?\n''@').Groups[1].Value
if (-not $src) { throw 'Embedded decoder not found' }
$test = @'
public static class RoundTripTest {
    static System.Collections.Generic.Dictionary<string,object> C, E;
    static System.IO.BinaryWriter w;
    static int depth;
    static System.Collections.Generic.List<int> path = new System.Collections.Generic.List<int>();
    public static string Target; public static int TargetOffset = -1;
    const System.Reflection.BindingFlags NS = System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static;
    static System.Collections.Generic.Dictionary<string,object> D(object o) { return (System.Collections.Generic.Dictionary<string,object>)o; }
    static void Check(bool ok, string m) { if (!ok) throw new System.Exception("assertion failed: " + m); }

    // Bs.ServerLibrary PacketWriter 규칙(빌드 26752678 설치본에서 디컴파일해 확인): zigzag varint, 개수는 ushort varint, 메시지는 null 비트(bool) + 본문.
    static void VarU(ulong v) { while (v >= 0x80) { w.Write((byte)(v | 0x80)); v >>= 7; } w.Write((byte)v); }
    static void I32(int v) { VarU((uint)((v << 1) ^ (v >> 31))); }
    static void I64(long v) { VarU((ulong)((v << 1) ^ (v >> 63))); }
    static void U16(int n) { VarU((uint)(ushort)n); }
    static void Str(string s) { if (s == null) { I32(-1); return; } var b = System.Text.Encoding.UTF8.GetBytes(s); I32(b.Length); w.Write(b); }

    static bool Prim(string t, int v) {
        switch (t) {
            case "bool": w.Write(v != 1); return true;
            case "sbyte": w.Write((sbyte)(v == 0 ? -128 : 127)); return true;
            case "byte": w.Write((byte)(v == 0 ? 0 : 255)); return true;
            case "short": I32(v == 0 ? short.MinValue : short.MaxValue); return true;
            case "ushort": U16(v == 0 ? 0 : 65535); return true;
            case "int": I32(v == 0 ? int.MinValue : v == 1 ? int.MaxValue : -1); return true;
            case "long": I64(v == 0 ? long.MinValue : v == 1 ? long.MaxValue : -1); return true;
            case "float": w.Write(v == 0 ? -1.5f : 3.25f); return true;
            case "double": w.Write(v == 0 ? -1.5 : 3.25); return true;
            case "string": Str(v == 0 ? "" : v == 1 ? new string('가', 60) : null); return true; // 180바이트(>128 경로)
            case "DateTime": case "TimeSpan": w.Write(v == 0 ? long.MinValue : 0x0123456789ABCDEFL); return true;
        }
        return false;
    }
    static int EnumMax(string t) {
        object o; int max = 0;
        if (E.TryGetValue(t.Substring(t.LastIndexOf('.') + 1), out o)) foreach (string k in D(o).Keys) max = System.Math.Max(max, int.Parse(k));
        return max;
    }
    static void Msg(string cn, bool present) {
        if (!present || depth > 12) { w.Write(false); return; }
        w.Write(true); Body(cn);
    }
    static void Body(string cn) {
        depth++;
        var desc = D(C[cn]); var fields = D(desc["fields"]); var order = (object[])desc["order"];
        bool target = cn == Target && PathIs(2, 4, 0, 1);
        for (int i = 0; i < order.Length; i++) {
            var pair = (object[])order[i];
            if (target && i == 0 && TargetOffset < 0 && path.Count > 0) TargetOffset = (int)w.BaseStream.Position; // 첫 원소의 첫 필드
            path.Add(i);
            Value((string)fields[(string)pair[0]], (string)pair[1]);
            path.RemoveAt(path.Count - 1);
        }
        depth--;
    }
    static bool PathIs(params int[] p) {
        if (path.Count != p.Length) return false;
        for (int i = 0; i < p.Length; i++) if (path[i] != p[i]) return false;
        return true;
    }
    static void Value(string t, string kind) {
        t = t.Trim();
        if (kind == "enum") {
            if (t.StartsWith("List<")) { U16(2); I32(0); I32(EnumMax(t.Substring(5, t.Length - 6))); return; }
            I32(EnumMax(t)); return;
        }
        if (Prim(t, 1)) return;
        if (t == "byte[]") { I32(3); w.Write(new byte[] { 0, 0x80, 0xFF }); return; }
        if (t == "int[]") { U16(2); I32(int.MinValue); I32(int.MaxValue); return; }
        int n = depth > 8 ? 0 : 3;
        if (t.EndsWith("[]")) { U16(n); for (int i = 0; i < n; i++) Msg(t.Substring(0, t.Length - 2), i != 1); return; }
        if (t.StartsWith("Dictionary<")) {
            string body = t.Substring(11, t.Length - 12); int comma = body.IndexOf(',');
            string kt = body.Substring(0, comma).Trim(), vt = body.Substring(comma + 1).Trim();
            U16(n);
            for (int i = 0; i < n; i++) { Prim(kt, i); Value(vt, "value"); }
            return;
        }
        if (t.StartsWith("List<") || t.StartsWith("HashSet<")) {
            string inner = t.Substring(t.IndexOf('<') + 1, t.Length - t.IndexOf('<') - 2).Trim();
            U16(n);
            for (int i = 0; i < n; i++) { if (!Prim(inner, i)) Msg(inner, i != 1); }
            return;
        }
        Msg(t, true);
    }
    static string FieldType(string cn, int i) { var d = D(C[cn]); return (string)D(d["fields"])[(string)((object[])((object[])d["order"])[i])[0]]; }
    static string Unlist(string t) { return t.StartsWith("List<") ? t.Substring(5, t.Length - 6) : t; }

    public static byte[] Build(string json) {
        var root = D(new System.Web.Script.Serialization.JavaScriptSerializer { MaxJsonLength = int.MaxValue }.DeserializeObject(json));
        C = D(root["classes"]); E = D(root["enums"]);
        string ack = (string)D(D(root["packet_ids"])["403"])["class"];
        // 보고된 실패 경로: ack #3 > #5 > #1 > #2(List) 원소
        string ud = FieldType(ack, 2), c5 = FieldType(ud, 4), c1 = FieldType(c5, 0), list = FieldType(c1, 1);
        Check(list.StartsWith("List<"), "reported path is a List");
        Target = Unlist(list); TargetOffset = -1;
        var ms = new System.IO.MemoryStream(); w = new System.IO.BinaryWriter(ms); depth = 0; path.Clear();
        Body(ack); w.Flush();
        Check(TargetOffset > 0, "target element written");
        return ms.ToArray();
    }

    static object Decode(byte[] b, string json, out int end) {
        var sc = typeof(SsMyInfo).GetMethod("LoadSchema", NS).Invoke(null, new object[] { json });
        var rdType = typeof(SsMyInfo).GetNestedType("Rd", System.Reflection.BindingFlags.NonPublic);
        var rd = System.Activator.CreateInstance(rdType, true);
        rdType.GetField("B").SetValue(rd, b);
        ((System.Collections.IList)typeof(SsMyInfo).GetField("DiagPath", NS).GetValue(null)).Clear();
        ((System.Collections.IList)typeof(SsMyInfo).GetField("DiagLists", NS).GetValue(null)).Clear();
        string pc = (string)sc.GetType().GetField("PacketClass").GetValue(sc);
        object o = typeof(SsMyInfo).GetMethod("DecodeClass", NS).Invoke(null, new object[] { rd, sc, pc });
        end = (int)rdType.GetField("P").GetValue(rd);
        return o;
    }
    static System.Collections.Generic.List<object> L(object o) { return (System.Collections.Generic.List<object>)o; }

    public static string Run(string json) {
        byte[] b = Build(json);
        int end; object ack = Decode(b, json, out end);
        Check(end == b.Length, "consumed whole body " + end + "/" + b.Length);
        var rewards = L(L(L(L(ack)[2])[4])[0])[1];
        var list = L(rewards);
        Check(list.Count == 3 && list[1] == null && list[0] != null && list[2] != null, "reward list 3 entries, middle null");
        var first = L(list[0]);
        Check(first.Count == 5, "element has 5 fields");
        Check(first[0] is EnumV && ((EnumV)first[0]).N != null, "enum decoded with a name");
        Check(object.Equals(first[1], (long)int.MaxValue), "int extreme");
        Check(object.Equals(first[3], long.MaxValue), "long extreme");
        string ok = "roundtrip " + b.Length + "B, reward element @" + TargetOffset;

        // 대조군: 보고된 위치(원소 #1 의 첫 필드)에 끝나지 않는 varint 를 넣으면 같은 경로에서 InvalidDataException
        var bad = (byte[])b.Clone();
        for (int i = 0; i < 5; i++) bad[TargetOffset + i] = 0xFF;
        try { Decode(bad, json, out end); throw new System.Exception("corrupted body decoded"); }
        catch (System.Reflection.TargetInvocationException ex) {
            Check(ex.InnerException is System.IO.InvalidDataException, "InvalidDataException");
            var diag = (System.Collections.Generic.List<string>)typeof(SsMyInfo).GetField("DiagPath", NS).GetValue(null);
            Check(diag.Count == 5, "path depth 5, got " + diag.Count);
            string last = diag[4];
            Check(last.StartsWith(Target + " #1 (") && last.Contains("@" + TargetOffset + "/"), "deepest = element field #1 at offset: " + last);
            Check(diag[3].Contains(" #2 (List<" + Target + ">)"), "list field #2");
            string lists = (string)typeof(SsMyInfo).GetMethod("ListSummary", NS).Invoke(null, null);
            Check(lists.EndsWith("[1/3]"), "list position recorded: " + lists);
            ok += "; corrupted -> " + ex.InnerException.GetType().Name + " at list " + lists;
        }
        return ok;
    }

    public static string Reassembly() {
        var flowType = typeof(SsMyInfo).GetNestedType("Flow", System.Reflection.BindingFlags.NonPublic);
        var segType = typeof(SsMyInfo).GetNestedType("Seg", System.Reflection.BindingFlags.NonPublic);
        var assemble = typeof(SsMyInfo).GetMethod("Assemble", NS);
        System.Func<uint, byte[], object> seg = (s, p) => { var o = System.Activator.CreateInstance(segType, true); segType.GetField("Seq").SetValue(o, s); segType.GetField("P").SetValue(o, p); return o; };
        System.Func<object[], object> flow = segs => {
            var f = System.Activator.CreateInstance(flowType, true);
            var l = (System.Collections.IList)flowType.GetField("Segs").GetValue(f);
            foreach (var s in segs) l.Add(s);
            return f;
        };
        // 같은 내용의 중복(pktmon 이 여러 구성 요소에서 받은 사본): 차이 0
        var f1 = flow(new object[] { seg(1000, new byte[] { 1, 2, 3, 4 }), seg(1000, new byte[] { 1, 2, 3, 4 }), seg(1002, new byte[] { 3, 4, 5 }) });
        var out1 = (System.Collections.Generic.List<byte[]>)assemble.Invoke(null, new object[] { f1 });
        Check(out1.Count == 1 && out1[0].Length == 5 && out1[0][4] == 5, "dup assemble");
        Check((long)flowType.GetField("OverlapDiff").GetValue(f1) == 0 && (long)flowType.GetField("Gaps").GetValue(f1) == 0, "no diff");
        // 겹친 부분 내용이 다름: 먼저 받은 것을 유지하고 다른 바이트 수를 센다
        var f2 = flow(new object[] { seg(1000, new byte[] { 1, 2, 3, 4 }), seg(1002, new byte[] { 9, 4, 5 }), seg(1001, new byte[] { 7, 3 }) });
        var out2 = (System.Collections.Generic.List<byte[]>)assemble.Invoke(null, new object[] { f2 });
        Check(out2.Count == 1 && out2[0][1] == 2 && out2[0][2] == 3 && out2[0][4] == 5, "first copy kept");
        Check((long)flowType.GetField("OverlapDiff").GetValue(f2) == 2, "two differing bytes, got " + flowType.GetField("OverlapDiff").GetValue(f2));
        // 빈 구간: 조각을 나누고 센다
        var f3 = flow(new object[] { seg(1000, new byte[] { 1, 2 }), seg(1010, new byte[] { 3 }) });
        var out3 = (System.Collections.Generic.List<byte[]>)assemble.Invoke(null, new object[] { f3 });
        Check(out3.Count == 2 && (long)flowType.GetField("Gaps").GetValue(f3) == 1, "gap split");
        return "reassembly dup/diff/gap";
    }
}
'@
$work = Join-Path $root '_tmp'
[void][IO.Directory]::CreateDirectory($work)
$env:TEMP = [IO.Path]::GetFullPath($work); $env:TMP = $env:TEMP
Add-Type -TypeDefinition ($src + "`n" + $test) -Language CSharp -ReferencedAssemblies 'System.Web.Extensions'

$encoded = [regex]::Match($text, '\$schemaB64 = ''([^'']+)''').Groups[1].Value
$stream = New-Object IO.MemoryStream (,[Convert]::FromBase64String($encoded))
$gzip = New-Object IO.Compression.GZipStream ($stream, [IO.Compression.CompressionMode]::Decompress)
$reader = New-Object IO.StreamReader ($gzip, [Text.Encoding]::UTF8)
try { $schema = $reader.ReadToEnd() } finally { $reader.Dispose(); $stream.Dispose() }
$build = [regex]::Match($text, "\`$BuildLabel = '(\d+)'").Groups[1].Value
if ($schema -notmatch ('"build":"' + $build + '"')) { throw "schema build label differs from `$BuildLabel $build" }

$results = @()
$results += [RoundTripTest]::Run($schema)
$results += [RoundTripTest]::Reassembly()

# appmanifest 빌드 번호(함수만 꺼내 실행)
$ast = [Management.Automation.Language.Parser]::ParseInput($text, [ref]$null, [ref]$null)
$fn = $ast.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-GameBuildId' }, $true) | Select-Object -First 1
if (-not $fn) { throw 'Get-GameBuildId not found' }
. ([ScriptBlock]::Create($fn.Extent.Text))
$lib = Join-Path $work 'steamtest\steamapps'
$game = Join-Path $lib 'common\StarSavior'
[void][IO.Directory]::CreateDirectory($game)
[IO.File]::WriteAllText((Join-Path $game 'StarSavior.exe'), '')
[IO.File]::WriteAllText((Join-Path $lib 'appmanifest_1.acf'), "`"AppState`"`n{`n`t`"installdir`"`t`t`"OtherGame`"`n`t`"buildid`"`t`t`"111`"`n}")
[IO.File]::WriteAllText((Join-Path $lib 'appmanifest_2.acf'), "`"AppState`"`n{`n`t`"buildid`"`t`t`"26752678`"`n`t`"installdir`"`t`t`"StarSavior`"`n}")
$got = Get-GameBuildId (Join-Path $game 'StarSavior.exe')
if ($got -ne '26752678') { throw "game build: $got" }
if ($null -ne (Get-GameBuildId (Join-Path $work 'nowhere\x.exe'))) { throw 'game build should be null' }
Remove-Item -LiteralPath (Join-Path $work 'steamtest') -Recurse -Force
$results += 'appmanifest buildid'

$results | ForEach-Object { Write-Output ('PASS ' + $_) }
