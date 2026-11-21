"""gen_schema.py 시험: 중첩 클래스가 바깥 Serialize 보다 앞에 있어도 바깥 필드 순서를 읽는지.

  python -I tests/gen_schema_test.py [<decompiled 폴더>]

폴더를 주면 실제 디컴파일에서 LOGIN_ACK > UserData #5 형식이 29개 필드인지도 본다(빌드 26752678 클라 기준).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import gen_schema  # noqa: E402

SAMPLE = """
public sealed class OBF_1 : ISerializable
{
	public sealed class OBF_2 : ISerializable
	{
		public OBF_3 OBF_10;

		public int OBF_11;

		void ISerializable.Serialize(IPacketStream OBF_9)
		{
			OBF_9.PutOrGet<OBF_3>(ref OBF_10);
			OBF_9.PutOrGet(ref OBF_11);
		}
	}

	public int OBF_20;

	public OBF_2 OBF_21;

	public long OBF_22;

	void ISerializable.Serialize(IPacketStream OBF_9)
	{
		OBF_9.PutOrGet(ref OBF_20);
		OBF_9.PutOrGet<OBF_2>(ref OBF_21);
		OBF_9.PutOrGet(ref OBF_22);
	}
}
"""


def main():
    classes, _, _ = gen_schema.parse(SAMPLE)
    fields, order = gen_schema.class_desc("OBF_1", classes["OBF_1"])
    assert order == [("OBF_20", "value"), ("OBF_21", "value"), ("OBF_22", "value")], order
    assert fields == {"OBF_20": "int", "OBF_21": "OBF_2", "OBF_22": "long"}, fields
    f2, o2 = gen_schema.class_desc("OBF_2", classes["OBF_2"])
    assert o2 == [("OBF_10", "value"), ("OBF_11", "value")], o2
    print("PASS nested class before outer Serialize")

    if len(sys.argv) > 1:
        root = Path(sys.argv[1])
        schema, out_c, packet = gen_schema.generate(root, "test")
        ack = out_c[packet]
        ud = ack[0][ack[1][2][0]]
        c5 = out_c[ud][0][out_c[ud][1][4][0]]
        n = len(out_c[c5][1])
        assert n == 29, (c5, n)
        print("PASS decompiled UserData #5 (%s) has %d fields" % (c5, n))


if __name__ == "__main__":
    main()
