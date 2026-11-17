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
