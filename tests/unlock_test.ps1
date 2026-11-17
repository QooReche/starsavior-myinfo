$ErrorActionPreference = 'Stop'
# Compile only the embedded decoder; never run capture/elevation/browser code.
$text = Get-Content -Encoding utf8 (Join-Path $PSScriptRoot '../myinfo.ps1') -Raw
$src = [regex]::Match($text, '(?s)\$src = @''\r?\n(.*?)\r?\n''@').Groups[1].Value
if (-not $src) { throw 'Embedded decoder not found' }
$test = @'
public static class UnlockTest {
    static System.Collections.Generic.List<object> Row(params object[] a) { return new System.Collections.Generic.List<object>(a); }
    static void Equal(object a, object b) { if (!object.Equals(a,b)) throw new System.Exception("assertion failed"); }
    static System.Collections.Generic.Dictionary<string,object> D(object o) { return (System.Collections.Generic.Dictionary<string,object>)o; }
    static string FieldType(object c, int i) { var d=D(c); return (string)D(d["fields"])[(string)((object[])((object[])d["order"])[i])[0]]; }
    public static void Schema(string json) {
        var root=D(new System.Web.Script.Serialization.JavaScriptSerializer().DeserializeObject(json));
        var classes=D(root["classes"]); var ack=classes[(string)D(D(root["packet_ids"])["403"])["class"]];
        var ud=classes[FieldType(ack,2)]; string list=FieldType(ud,6);
        if(!list.StartsWith("List<")) throw new System.Exception("history schema changed");
        var history=classes[list.Substring(5,list.Length-6)];
        Equal(FieldType(history,0),"int"); for(int i=1;i<4;i++)Equal(FieldType(history,i),"bool");
        string units=FieldType(ud,1), unitType=units.Substring(units.IndexOf(',')+1).Trim().TrimEnd('>');
        Equal(FieldType(classes[unitType],14),"bool");
        var flags=System.Reflection.BindingFlags.NonPublic|System.Reflection.BindingFlags.Static;
        var sc=typeof(SsMyInfo).GetMethod("LoadSchema",flags).Invoke(null,new object[]{json});
        foreach(int id in new int[]{11003017,11003018}) {
            var stream=new System.IO.MemoryStream();var writer=new System.IO.BinaryWriter(stream);
            writer.Write((byte)1);writer.Write(true);
            uint encoded=(uint)id<<1; // protocol int = zigzag varint; count = unsigned varint
            while(encoded>=128){writer.Write((byte)(encoded|128));encoded>>=7;}writer.Write((byte)encoded);
            writer.Write(false);writer.Write(false);writer.Write(false);
            var rdType=typeof(SsMyInfo).GetNestedType("Rd",System.Reflection.BindingFlags.NonPublic);
            var rd=System.Activator.CreateInstance(rdType,true);
            rdType.GetField("B").SetValue(rd,stream.ToArray());
            var decoded=typeof(SsMyInfo).GetMethod("DecodeValue",flags).Invoke(null,new object[]{rd,sc,list,"value"});
            Equal(SsMyInfo.SynchroUnlocked(Row(null,null,null,null,null,null,decoded)),id==11003018);
            Equal(rdType.GetField("P").GetValue(rd),(int)stream.Length);
        }
    }
    public static void Run() {
        var empty = Row(); var ud = Row(null,null,null,null,null,null,empty);
        Equal(SsMyInfo.SynchroUnlocked(ud),false);
        empty.Add(Row(11003017L,false,false,false)); Equal(SsMyInfo.SynchroUnlocked(ud),false);
        empty.Add(Row(11003018L,false,false,false)); Equal(SsMyInfo.SynchroUnlocked(ud),true);
        empty.Add(null); Equal(SsMyInfo.SynchroUnlocked(ud),null);
        Equal(SsMyInfo.SynchroUnlocked(Row()),null); ud[6]=null; Equal(SsMyInfo.SynchroUnlocked(ud),null);
        ud[6]=Row(Row("11003018",false,false,false)); Equal(SsMyInfo.SynchroUnlocked(ud),null);
        while(ud.Count<32)ud.Add(null);
        ud[1]=new System.Collections.Generic.Dictionary<string,object>(); ud[2]=Row();
        ud[14]=new System.Collections.Generic.Dictionary<string,object>();
        ud[19]=Row(0L,0L,0L,Row(),Row()); ud[21]=Row(0L,0L,Row()); ud[31]=Row();
        var ack=Row(null,null,ud);
        var js=new System.Web.Script.Serialization.JavaScriptSerializer();
        foreach(object history in new object[]{null,Row(),Row(Row(11003018L,false,false,false))}) {
            ud[6]=history;
            var root=(System.Collections.Generic.Dictionary<string,object>)js.DeserializeObject(SsMyInfo.Export(ack,"synthetic"));
            var link=(System.Collections.Generic.Dictionary<string,object>)root["star_link"];
            Equal(link.ContainsKey("unlocked"),history!=null);
            if(history!=null)Equal(link["unlocked"],((System.Collections.Generic.List<object>)history).Count>0);
            Equal(root["format"],"ss-myinfo-v1"); Equal(link["level"],0);
        }
        var unit=Row(1001L,40L,2L,0L,0L,Row(0L,1L,1L,1L,0L),0L,0L,Row(),Row(),0L,0L,false,0L,true);
        ((System.Collections.Generic.Dictionary<string,object>)ud[1]).Add("1001",unit);
        var exported=(System.Collections.Generic.Dictionary<string,object>)js.DeserializeObject(SsMyInfo.Export(ack,"synthetic"));
        var units=(object[])exported["units"];
        Equal(((System.Collections.Generic.Dictionary<string,object>)units[0])["blossom"],true);
    }
}
'@
$work = Join-Path $PSScriptRoot '../_tmp'
[void][IO.Directory]::CreateDirectory($work)
$env:TEMP = [IO.Path]::GetFullPath($work); $env:TMP = $env:TEMP
Add-Type -TypeDefinition ($src + "`n" + $test) -Language CSharp -ReferencedAssemblies 'System.Web.Extensions'
[UnlockTest]::Run()
$encoded = [regex]::Match($text, '\$schemaB64 = ''([^'']+)''').Groups[1].Value
$stream = New-Object IO.MemoryStream (,[Convert]::FromBase64String($encoded))
$gzip = New-Object IO.Compression.GZipStream ($stream, [IO.Compression.CompressionMode]::Decompress)
$reader = New-Object IO.StreamReader ($gzip)
try { [UnlockTest]::Schema($reader.ReadToEnd()) } finally { $reader.Dispose(); $stream.Dispose() }
Write-Output 'PASS included/absent/empty/missing/null/malformed histories, export tri-state, actual blossom'
