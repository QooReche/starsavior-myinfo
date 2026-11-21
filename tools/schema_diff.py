"""두 내장 스키마(JSON)를 LOGIN_ACK 부터 나란히 걸으며 필드 개수·형식·종류(enum/value)·enum 값을 비교한다.

이름은 빌드마다 다시 난독화되므로 이름이 아니라 위치(필드 순번)로 짝을 짓는다.
  python -I tools/schema_diff.py <옛.json> <새.json>
차이가 없으면 'no differences' 를 출력하고 0, 있으면 1 로 끝난다.
"""
import json
import re
import sys

M = re.compile(r"[\u0d00-\u0d7f]+(?:\.[\u0d00-\u0d7f]+)*")


def main(pa, pb):
    A = json.load(open(pa, encoding="utf-8"))
    B = json.load(open(pb, encoding="utf-8"))
    shape = lambda t: M.sub("X", t)
    pairs = [(A["packet_ids"]["403"]["class"], B["packet_ids"]["403"]["class"], "ACK")]
    seen, epairs, diffs = set(), {}, []
    while pairs:
        a, b, path = pairs.pop(0)
        if (a, b) in seen:
            continue
        seen.add((a, b))
        ca, cb = A["classes"][a], B["classes"][b]
        oa, ob = ca["order"], cb["order"]
        if len(oa) != len(ob):
            diffs.append("FIELDCOUNT %s %d -> %d" % (path, len(oa), len(ob)))
        for i in range(max(len(oa), len(ob))):
            ta = (shape(ca["fields"][oa[i][0]]), oa[i][1]) if i < len(oa) else None
            tb = (shape(cb["fields"][ob[i][0]]), ob[i][1]) if i < len(ob) else None
            if ta != tb:
                diffs.append("FIELD %s[%d] %s -> %s" % (path, i, ta, tb))
                continue
            ra, rb = M.findall(ca["fields"][oa[i][0]]), M.findall(cb["fields"][ob[i][0]])
            for x, y in zip(ra, rb):
                x1, y1 = x.split(".")[-1], y.split(".")[-1]
                if oa[i][1] == "enum" or x1 in A["enums"]:
                    epairs[(x1, y1)] = "%s[%d]" % (path, i)
                else:
                    pairs.append((x, y, "%s[%d]" % (path, i)))
    for (x, y), p in epairs.items():
        if A["enums"][x] != B["enums"][y]:
            diffs.append("ENUM %s %s -> %s" % (p, A["enums"][x], B["enums"][y]))
    print("classes compared", len(seen), "enums compared", len(epairs))
    for d in diffs:
        print(d)
    print("no differences" if not diffs else "%d differences" % len(diffs))
    return 1 if diffs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
