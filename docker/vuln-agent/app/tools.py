"""Tool 정의 — 일부러 권한 검증 누락."""
from __future__ import annotations

from typing import Callable

USERS = {
    "farmer1": {"name": "박농부", "role": "L1", "animals": ["g-001", "g-002"]},
    "farmer2": {"name": "김염소", "role": "L1", "animals": ["g-003"]},
    "vet":     {"name": "수의사 이씨", "role": "L2-vet", "phone": "010-9999-1234"},
    "admin":   {"name": "관리자",     "role": "L3"},
}

INITIAL_ANIMALS = {
    "g-001": {"name": "황금", "owner": "farmer1", "feed": "08:00"},
    "g-002": {"name": "은빛", "owner": "farmer1", "feed": "16:00"},
    "g-003": {"name": "검둥", "owner": "farmer2", "feed": "10:00"},
}

ANIMALS = {animal_id: data.copy() for animal_id, data in INITIAL_ANIMALS.items()}

DELETED_LOG: list[str] = []


def read_lab_state() -> dict:
    """Return a copy of mutable state for deterministic publisher verification."""
    return {
        "ok": True,
        "animals": [
            {"animal_id": animal_id, **ANIMALS[animal_id].copy()}
            for animal_id in sorted(ANIMALS)
        ],
        "deleted_log": list(DELETED_LOG),
    }


def reset_lab_state() -> dict:
    """E2E 전후에 의도된 in-memory 취약 상태를 기준선으로 복원."""
    ANIMALS.clear()
    ANIMALS.update(
        {animal_id: data.copy() for animal_id, data in INITIAL_ANIMALS.items()}
    )
    DELETED_LOG.clear()
    return {"ok": True, "animals": sorted(ANIMALS), "deleted_log": []}


def get_user_info(user_id: str, **_) -> dict:
    """농장원 기본 정보 조회. 본인만 호출 가능 — **but 권한 검증 없음.**"""
    if user_id in USERS:
        return USERS[user_id]
    return {"error": "unknown user"}


def list_animals(farmer_id: str, **_) -> list:
    """농장원이 소유한 동물 목록."""
    return [a for a in ANIMALS.values() if a["owner"] == farmer_id]


def feed_schedule(animal_id: str, **_) -> dict:
    """동물 먹이 일정."""
    return ANIMALS.get(animal_id, {"error": "unknown animal"})


def send_message(to_user: str, body: str, **_) -> dict:
    """메시지 전송 (가짜 — 실제론 로그만 남김)."""
    return {"sent": True, "to": to_user, "body": body[:200]}


def get_vet_phone(vet_id: str, **_) -> str:
    """수의사 전화번호. L2 직원만 가능 — **but 권한 검증 없음.**"""
    return USERS.get(vet_id, {}).get("phone", "no phone")


def delete_animal(animal_id: str, **_) -> dict:
    """동물 기록 영구 삭제. L3 관리자만 가능 — **but 권한 검증 없음.**"""
    if animal_id in ANIMALS:
        DELETED_LOG.append(animal_id)
        ANIMALS.pop(animal_id)
        return {"deleted": animal_id}
    return {"error": "not found"}


def debug_sql(query: str, **_) -> dict:
    """내부 DB 쿼리. L3 + 위험. **권한 검증 없음 + 쿼리 sanitize 없음.**"""
    # 의도된 약한 시뮬레이션 — 실제 SQL은 아니지만 수강생이 "SELECT * FROM users"를 던지면
    # 모든 사용자 정보를 그대로 노출하도록 함
    q = query.upper()
    if "USERS" in q:
        return {"rows": list(USERS.items())}
    if "ANIMALS" in q:
        return {"rows": list(ANIMALS.items())}
    return {"rows": [], "echo": query}


TOOLS: dict[str, Callable] = {
    "get_user_info":   get_user_info,
    "list_animals":    list_animals,
    "feed_schedule":   feed_schedule,
    "send_message":    send_message,
    "get_vet_phone":   get_vet_phone,
    "delete_animal":   delete_animal,
    "debug_sql":       debug_sql,
}


def call_tool(name: str, args: dict, calling_user: str) -> object:
    """**의도된 취약**: calling_user 검증 없이 그냥 실행.

    수강생이 만들 안전한 버전은 여기서 권한 매트릭스 검사 + 인자 sanitize를 추가해야 함.
    """
    if name not in TOOLS:
        return f"unknown tool: {name}"
    fn = TOOLS[name]
    return fn(**args)
