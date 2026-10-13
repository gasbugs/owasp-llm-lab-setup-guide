"""Thread-safe operation-scoped progress from real preparation/deletion boundaries."""
from contextvars import ContextVar
from functools import wraps
import inspect
import threading
from uuid import UUID

PLANS = {
 ('P02', 'prepare'): [
  ('AWS 계정 확인', '현재 AWS 계정과 실습 전용 자원 이름을 확인합니다.'),
  ('기존 자원 확인', '기존 저장소·역할·Knowledge Base의 소유권과 설정을 검사합니다.'),
  ('S3 원문 저장소 준비', '문서 원문을 보관할 S3 버킷을 준비합니다.'),
  ('S3 접근 설정 확인', '외부 공개를 막고 미션 소유 태그를 확인합니다.'),
  ('벡터 저장소 준비', '문서를 숫자 벡터로 보관할 저장소를 준비합니다.'),
  ('벡터 인덱스 준비', '1024차원 임베딩을 검색할 인덱스를 준비합니다.'),
  ('IAM 역할 준비', 'Bedrock이 미션 문서와 벡터 인덱스에 접근할 권한을 준비합니다.'),
  ('Knowledge Base 준비', '문서 저장소와 벡터 인덱스를 연결하고 활성화 상태를 기다립니다.'),
  ('문서 연결 준비', 'Knowledge Base가 사용할 S3 문서 경로를 연결합니다.'),
  ('연결 검증', '저장소·권한·검색 연결이 같은 미션 설정을 사용하는지 확인합니다.')],
 ('P03', 'prepare'): [
  ('AWS 계정 확인', '이번 문서 검색 실습을 실행할 AWS 계정을 확인합니다.'),
  ('기존 자원 확인', '검색 실습 전용 저장소와 권한의 소유권을 확인합니다.'),
  ('S3 원문 저장소 준비', '현재 문서를 저장할 S3 버킷과 접근 설정을 준비합니다.'),
  ('벡터 저장소 준비', '문서 임베딩을 보관할 벡터 저장소를 준비합니다.'),
  ('벡터 인덱스 준비', '문서 벡터를 검색할 인덱스를 준비합니다.'),
  ('IAM 역할 준비', 'Bedrock의 문서 조회·임베딩·벡터 저장 권한을 준비합니다.'),
  ('Knowledge Base 준비', '검색 연결을 만들거나 확인하고 활성화 상태를 기다립니다.'),
  ('문서 연결 준비', '검색에 사용할 S3 문서 경로를 연결합니다.'),
  ('현재 문서 준비', '현재 정책 문서를 저장하거나 기존 원문을 확인합니다.'),
  ('문서 동기화', 'Bedrock이 문서를 임베딩하고 검색 저장소에 반영할 때까지 기다립니다.'),
  ('검색 데이터 확인', '문서가 벡터 인덱스에 반영됐는지 확인합니다.'),
  ('준비 기록 저장', '완료된 동기화 작업과 문서 경로를 실행 기록에 저장합니다.')],
 ('P04', 'prepare'): [
  ('AWS 계정 확인', 'Guardrail을 준비할 AWS 계정을 확인합니다.'),
  ('기존 정책 확인', '미션 전용 정책의 소유권과 이메일 처리 설정을 확인합니다.'),
  ('Guardrail 준비', '출력 이메일을 비식별화하는 정책을 만들거나 기존 정책을 사용합니다.'),
  ('정책 활성화 확인', 'AWS Guardrail이 READY 상태가 될 때까지 기다립니다.'),
  ('정책 기록 저장', '정책 설정과 AWS 준비 기록을 저장합니다.')],
}
_STORAGE_DELETE = [
 ('삭제 범위 확인', '미션 소유 자원과 원문 경로를 검사하고 실행 중인 작업이 없는지 확인합니다.'),
 ('문서 연결 삭제', 'Knowledge Base의 문서 연결을 삭제하고 삭제 완료를 기다립니다.'),
 ('Knowledge Base 삭제', '미션의 검색 연결을 삭제하고 삭제 완료를 기다립니다.'),
 ('원문 저장소 삭제', '미션 문서와 전용 S3 버킷을 삭제합니다.'),
 ('벡터 인덱스 삭제', '미션 문서의 검색 벡터 인덱스를 삭제합니다.'),
 ('벡터 저장소 삭제', '미션 전용 벡터 버킷을 삭제합니다.'),
 ('IAM 역할 삭제', '미션 전용 접근 정책과 역할을 삭제합니다.'),
 ('삭제 결과 확인', 'AWS 자원이 남아 있지 않은지 확인하고 삭제 기록을 저장합니다.')]
for problem in ('P02', 'P03'):
 PLANS[(problem, 'delete')] = _STORAGE_DELETE
PLANS[('P04', 'delete')] = [
 ('삭제 범위 확인', '미션 전용 Guardrail의 소유권과 현재 정책을 확인합니다.'),
 ('Guardrail 삭제', '미션 Guardrail의 DRAFT 정책을 삭제합니다.'),
 ('삭제 결과 확인', '정책 삭제를 확인하고 삭제 기록을 저장합니다.')]

_context = ContextVar('resource_operation', default=None)
_lock = threading.Lock()
_records = {}


def step(number):
    key = _context.get()
    if key is None:
        return
    with _lock:
        record = _records[key]
        plan = PLANS[(record['practice_id'], record['action'])]
        if not record['current'] <= number <= len(plan):
            raise ValueError('invalid resource step transition')
        title, description = plan[number - 1]
        record.update(current=number, title=title, description=description)


def read(problem, operation_id):
    with _lock:
        record = _records.get(operation_id)
        if record is None or record['practice_id'] != problem:
            return {'state': 'waiting', 'operation_id': operation_id}
        return dict(record)


def tracked(problem, *, action='prepare'):
    def decorate(function):
        @wraps(function)
        def invoke(*args, **kwargs):
            bound = inspect.signature(function).bind(*args, **kwargs).arguments
            identifier = bound.get('operation_id', bound.get('execution_id'))
            UUID(identifier)
            selected = bound['problem'] if problem is None else problem
            plan = PLANS[(selected, action)]
            with _lock:
                if len(_records) >= 256:
                    victim = next((key for key, row in _records.items() if row['state'] != 'running'), None)
                    if victim is None:
                        raise RuntimeError('resource progress capacity reached')
                    del _records[victim]
                _records[identifier] = dict(practice_id=selected, operation_id=identifier,
                    action=action, current=0, total=len(plan) + 1, state='running',
                    title='요청 확인', description='서버가 AWS 자원 작업을 시작합니다.')
            token = _context.set(identifier)
            try:
                result = function(*args, **kwargs)
                with _lock:
                    _records[identifier].update(current=len(plan), state='provider_complete',
                        title='준비 응답 확인' if action == 'prepare' else '삭제 응답 확인',
                        description='AWS 작업이 끝났습니다. 실행 화면에서 최종 응답을 확인합니다.')
                return {**result, 'resource_progress': read(selected, identifier)}
            except Exception:
                with _lock:
                    _records[identifier]['state'] = 'error'
                raise
            finally:
                _context.reset(token)
        return invoke
    return decorate
