"""LOGIN_ACK(403) 해독 스키마 생성기.

디컴파일 폴더(<DLL>/<DLL>.decompiled.cs + identifier_mapping.json)에서
[PacketId(...kNKMPacket_LOGIN_ACK)] 클래스부터 도달 가능한 직렬화 클래스·enum 을 모아
myinfo.ps1 내장 스키마(JSON)를 만든다. 이름은 매핑을 거꾸로 적용해 게임 원래(말라얄람) 이름으로 쓴다.

  python -I tools/gen_schema.py <decompiled 폴더> <빌드 번호> <출력.json>

Serialize 본문에 PutOrGet/PutOrGetEnum 외의 문장이 있으면 멈춘다(형식 추정 금지).
"""
import json
import re
import sys
from pathlib import Path

DLLS = ["NKM.Templets", "NKM", "Star.Templets", "Cs.UnityShare", "Assembly-CSharp", "NKC"]
PRIMS = {"bool", "sbyte", "byte", "short", "ushort", "int", "long", "float", "double", "string", "DateTime", "TimeSpan"}
TOK = re.compile(r"OBF_\d+")


def load_sources(root):
    texts = []
    for d in DLLS:
        p = root / d / (d + ".decompiled.cs")
        if p.exists():
            texts.append(p.read_text(encoding="utf-8"))
    return "\n".join(texts)


def block(text, start):
    """start 이후 첫 '{' 부터 짝 맞는 '}' 까지의 본문."""
    i = text.index("{", start)
    depth = 0
    for j in range(i, len(text)):
        c = text[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[i + 1:j]
    raise ValueError("unbalanced")


def parse(text):
    classes, enums, packet = {}, {}, None
    for m in re.finditer(r"(\[PacketId\((\w+)\.(\w+)\)\]\s*)?public (?:sealed )?class (OBF_\d+) : ISerializable", text):
        name = m.group(4)
        if name in classes:
            raise ValueError("duplicate class " + name)
        classes[name] = block(text, m.end())
        if m.group(3) == "kNKMPacket_LOGIN_ACK":
            packet = name
    for m in re.finditer(r"public enum (OBF_\d+)(?:\s*:\s*\w+)?\s*\{", text):
        body = block(text, m.end() - 1)
        body = re.sub(r"//[^\n]*|/\*.*?\*/|\[[^\]]*\]", "", body, flags=re.S)
        vals, cur = {}, -1
        try:
            for item in [x.strip() for x in body.split(",") if x.strip()]:
                if "=" in item:
                    k, v = [x.strip() for x in item.split("=", 1)]
                    cur = int(re.sub(r"(?i)[ul]+$", "", v), 0)
                else:
                    k = item
                    cur += 1
                vals[str(cur)] = k
        except ValueError:
            vals = None  # 쓰이는 enum 이면 아래에서 멈춘다
        if m.group(1) in enums and enums[m.group(1)] != vals:
            raise ValueError("duplicate enum " + m.group(1))
        enums[m.group(1)] = vals
    return classes, enums, packet


def class_desc(name, body):
    ser = re.search(r"void ISerializable\.Serialize\(IPacketStream (\w+)\)", body)
    if not ser:
        raise ValueError(name + ": Serialize not found")
    decl_part = body[:ser.start()]
    fields = {}
    for m in re.finditer(r"public ([\w\.<>, \[\]?]+?) (OBF_\d+)(?: = [^;]+)?;", decl_part):
        fields[m.group(2)] = m.group(1).strip()
    stream = ser.group(1)
    order = []
    for stmt in [s.strip() for s in block(body, ser.end()).split(";") if s.strip()]:
        m = re.fullmatch(re.escape(stream) + r"\.(PutOrGet|PutOrGetEnum)(?:<([^()]+)>)?\(ref (OBF_\d+)\)", stmt)
        if not m:
            raise ValueError(name + ": unsupported statement: " + stmt)
        f = m.group(3)
        if f not in fields:
            raise ValueError(name + ": field not declared: " + f)
        order.append((f, "enum" if m.group(1) == "PutOrGetEnum" else "value"))
    return fields, order


def refs(t):
    """형식 문자열 안의 클래스/enum 이름(중첩 Outer.Inner 는 Inner)."""
    return [x.split(".")[-1] for x in re.findall(r"OBF_\d+(?:\.OBF_\d+)*", t)]


def generate(root, build):
    text = load_sources(root)
    mapping = json.loads((root / "identifier_mapping.json").read_text(encoding="utf-8"))
    rev = {}
    for k, v in mapping.items():
        if v in rev:
            raise ValueError("mapping not 1:1: " + v)
        rev[v] = k
    classes, enums, packet = parse(text)
    if not packet:
        raise ValueError("LOGIN_ACK class not found")
    out_c, used_enums, queue, seen = {}, [], [packet], set()
    while queue:
        cn = queue.pop(0)
        if cn in seen:
            continue
        seen.add(cn)
        fields, order = class_desc(cn, classes[cn])
        out_c[cn] = (fields, order)
        for f, kind in order:
            t = fields[f]
            for r in refs(t):
                if kind == "enum" or r in enums:
                    if enums.get(r) is None:
                        raise ValueError(cn + ": enum not found " + r)
                    if r not in used_enums:
                        used_enums.append(r)
                elif r in classes:
                    queue.append(r)
                else:
                    raise ValueError(cn + ": type not found " + t)
            base = re.sub(r"^(List|HashSet)<(.*)>$", r"\2", t)
            if kind == "value" and t not in PRIMS and t not in ("byte[]", "int[]") and not refs(t) \
                    and base not in PRIMS:
                raise ValueError(cn + ": unsupported type " + t)
    ren = lambda s: TOK.sub(lambda m: rev[m.group(0)], s)
    schema = {
        "build": build,
        "classes": {ren(cn): {"fields": {ren(f): ren(fields[f]) for f, _ in order},
                              "order": [[ren(f), k] for f, k in order]}
                    for cn, (fields, order) in out_c.items()},
        "enums": {ren(e): {k: ren(v) for k, v in enums[e].items()} for e in used_enums},
        "packet_ids": {"403": {"name": "kNKMPacket_LOGIN_ACK", "class": ren(packet)}},
    }
    return schema, out_c, packet


if __name__ == "__main__":
    root, build, out = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
    schema, _, _ = generate(root, build)
    out.write_text(json.dumps(schema, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    print(out, len(schema["classes"]), "classes", len(schema["enums"]), "enums")
