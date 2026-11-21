# 선택 필드 (ss-myinfo-v1)

- `star_link.unlocked`: boolean. LOGIN_ACK(403) `ack[2][6]`의 정상 해독된 이력 목록에서 `entry[0] == 11003018`이면 true, 없으면 false. 이력 누락·null·잘못된 구조는 필드를 생략하며 소비자는 null과 함께 unknown으로 처리함. 패킷 해독 실패는 JSON 자체를 만들지 않음.
- `units[].blossom`: boolean. 로그인 유닛 `rec[14]`의 실제 개화 여부. 없는 옛 자료에서 개화를 추측하지 않음.

기존 필드·형식 버전은 유지함. 닉네임·계정 식별자·원시 이력은 출력하지 않음.

## 근거와 범위

빌드 26610546의 내장 스키마: UserData의 7번째 필드는 List, 원소는 int·bool·bool·bool 순서임. `DecodeValue`는 목록 길이(U16)만큼 모두 읽고 int를 Int64로 해독함. `DecodeLoginAck`는 본문 전체 소비를 확인한 뒤에만 Export를 호출함.

- `CONTENTS_UNLOCK_TEMPLET.json:445-447`: CT_SYNCHRO / NORMAL_BATTLE_CLEAR / 11003018(SECTOR 3-15).
- `NKM.Templets.decompiled.cs:25984,20118-20131`: 이력 목록·스테이지 ID 직렬화. `:19987,20005`: 개화 bool.
- `NKC.decompiled.cs:540159-540163`: 로그인 때 기존 이력 사전을 Clear한 후 수신 목록으로 재구성함. 목록에 페이지·커서·부분 갱신 플래그가 없고 이 초기화 경로에 후속 페이지 요청도 없음. `:539509,579633`은 이 사전의 키 존재로 NORMAL_BATTLE_CLEAR를 판단함. 따라서 이 빌드의 정상 LOGIN_ACK 목록은 개방 판정에 필요한 전체 스냅샷으로 취급함. 서버 구현 자체는 미확인임.

운영 LOCKDOWN 등 별도 운영 제한은 이 값에 포함하지 않음. 빌드별 스키마·조건이 바뀌면 재검토가 필요함. 설치 빌드 26694967 확인 시 기록 빌드 26610546과 비교 대상 DLL 8개의 해시는 동일했음.

시험: `powershell -NoProfile -ExecutionPolicy Bypass -File tests/unlock_test.ps1`. 캡처·계정 정보 없이 내장 C#을 컴파일해 합성 해독 목록과 Export를 확인함.

## 빌드 26752678 (2026-11-21) 스키마 대조

결론: **LOGIN_ACK(403) 직렬화 형식은 26610546 과 같음.** 필드 추가·삭제·형식·순서·enum/value 구분·enum 값 차이 0. 내장 스키마는 26752678 디컴파일에서 다시 만들었고(새 난독 이름) `$BuildLabel` 을 26752678 로 바꿈. 해독 결과는 옛 스키마와 같음.

- 생성: `python -I tools/gen_schema.py <static-data>/decompiled 26752678 <출력.json>` — `[PacketId(kNKMPacket_LOGIN_ACK)]` 클래스부터 도달하는 82개 클래스·24개 enum 을 `Serialize` 본문(`PutOrGet`/`PutOrGetEnum`) 순서로 읽고 매핑을 거꾸로 적용. 그 밖의 문장이 있으면 멈춤.
- 생성기 검증: static-data 708f196(빌드 26610546) 디컴파일로 돌리면 기존 내장 스키마와 내용이 완전히 같음.
- 대조: `python -I tools/schema_diff.py 옛.json 새.json` — 이름이 아니라 필드 순번으로 짝지어 82개 클래스·24개 enum 비교, 차이 0. 보조로 `NKM.Templets`·`NKM` 디컴파일을 `OBF_번호` 를 가리고 비교하면 줄 차이 0(43,486줄·20,303줄 동일).
- 직렬화기: 설치본 `Bs.ServerLibrary.dll`(SHA256 `69537568fa2fa98852951a39b56f545e562ad1504ff6c5da09c5cf14fb271800`)의 `PacketReader/PacketWriter/Packet.ProcessRecv/Extract` 를 디컴파일해 해독기와 맞춰 봄 — zigzag varint(int·short·long), ushort varint 개수, 목록 원소마다 null 비트(bool), enum 은 int, DateTime/TimeSpan 은 8바이트 원값, 문자열은 short 길이(-1=null), 1024B 초과 본문은 LZ4 frame(64KB 블록 연결), 이하는 XOR. 해독기와 다른 점 없음.

진단 경로(rexian 1121)를 이름으로 풀면(옛 → 새 OBF):

| 진단 위치 | 26610546 | 26752678 | 정의 |
|---|---|---|---|
| LOGIN_ACK | OBF_20599 | OBF_2225 | ack: 결과 enum, string, UserData |
| #3 | OBF_17573 | OBF_22930 | UserData(53필드) |
| #5 | OBF_35338 | OBF_21836 | (보상 묶음, enum BST_*) |
| #1 | OBF_12229 | OBF_25311 | 보상 묶음: List×5 |
| #2 원소 | OBF_5646 | OBF_4241 | enum RT_*(OBF_35531.OBF_3035), int, enum 결과, long, long |

두 빌드에서 원소 클래스는 같은 줄(NKM.Templets:19891)에 같은 5필드로 있음. 따라서 이 실패는 **스키마 차이로 설명되지 않음.** 같은 진단에 `gap-count=9 gap-bytes=25504`, `malformed-IP=108`, pktmon 변환 «패킷 삭제 수 255» 가 있어 통신 기록 손상(LZ4 본문 일부가 잘못 들어가 그 뒤 해독이 어긋남) 가능성이 남음 — 원본 패킷이 없어 확정은 못 함(미확인).

이번에 진단을 보강함(기존 `decode-fail:` 줄은 그대로):

- 흐름 목록에 `gaps=`·`overlap-diff=`(겹쳐 받은 TCP 조각 중 내용이 다른 바이트 수), 집계에 `overlap-diff-bytes`·`game-flow-damaged`.
- `decode-fail-detail:` 줄 — 실패 경로의 목록 위치(`[i/n]`), LZ4 frame 플래그·블록 수·출력 크기, 통신 기록 손상 의심 여부.
- `game build=` — 실행 중인 게임의 Steam appmanifest buildid(숫자만)와 도구 스키마 빌드 비교.
- 해독 실패이면서 게임 흐름에 빈 구간·내용 불일치가 있으면 «한 번 더 실행» 안내를 먼저 보여 줌.

시험: `powershell -NoProfile -ExecutionPolicy Bypass -File tests/schema_roundtrip_test.ps1` — 내장 스키마로 PacketWriter 규칙대로 합성 LOGIN_ACK(모든 목록·사전 3개, null 원소 포함, int/long 극단값, 128B 초과 문자열)를 만들어 끝까지 해독; 보고 경로 원소 #1 에 끝나지 않는 varint 를 넣으면 같은 경로·위치에서 InvalidDataException; 재조립의 중복·불일치·빈 구간 집계; appmanifest buildid 읽기.
