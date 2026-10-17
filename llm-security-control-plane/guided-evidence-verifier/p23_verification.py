"""Read-only model-call evidence checks; normal AWS call plus isolated error fixture."""
import hashlib
from pathlib import Path
MODEL="us.amazon.nova-lite-v1:0"

def check(receipt, current, expected_runner, execution_id):
    if (receipt.get("activity_id") != "P23" or receipt.get("execution_id") != execution_id
        or receipt.get("closed") is not True or receipt.get("runner_digest") != expected_runner
        or current.get("runner_digest") != expected_runner or receipt.get("source_digest") != current.get("source_digest")):
        raise ValueError("execution identity mismatch")
    cases=receipt.get("cases", [])
    if [c.get("case_id") for c in cases] != ["normal","blank","provider-error"]:
        raise ValueError("case evidence incomplete")
    normal, blank, error=cases
    expected={"modelId":MODEL,"messages":[{"role":"user","content":[{"text":"계정 비밀번호를 바꾸는 이유를 한 문장으로 설명해 주세요."}]}],"inferenceConfig":{"maxTokens":64,"temperature":0}}
    response=normal.get("returned") or {}
    def client_region(case):
        clients=case.get("sdk_clients")
        return clients[0].get("region") if isinstance(clients,list) and len(clients)==1 and isinstance(clients[0],dict) else None
    normal_region=client_region(normal)
    error_region=client_region(error)
    valid_normal=(bool(normal_region) and normal.get("sdk_clients")==[{"service":"bedrock-runtime","region":normal_region,"native_sdk":True}] and normal.get("calls")==[expected] and normal.get("provider_attempts")==1
        and normal.get("provider_results")==[response] and normal.get("error") is None
        and bool(response.get("ResponseMetadata",{}).get("RequestId"))
        and not str(response.get("ResponseMetadata",{}).get("RequestId","")).startswith("contract-")
        and bool(response.get("output",{}).get("message",{}).get("content"))
        and isinstance(response.get("usage"),dict))
    valid_blank=(blank.get("sdk_clients")==[] and blank.get("calls")==[] and blank.get("provider_attempts")==0
        and blank.get("returned") is None and (blank.get("error") or {}).get("type")=="ValueError")
    error_call={**expected,"messages":[{"role":"user","content":[{"text":"연결 오류 처리 확인"}]}]}
    valid_error=(error_region == normal_region and error.get("sdk_clients")==[{"service":"bedrock-runtime","region":normal_region,"native_sdk":True}] and error.get("calls")==[error_call] and error.get("fixture_errors")==1
        and error.get("provider_attempts")==0 and error.get("provider_results")==[]
        and error.get("returned") is None and error.get("error")=={"type":"RuntimeError","message":"model unavailable"})
    checks=[valid_normal,valid_blank,valid_error]
    return {"activity_id":"P23","execution_id":execution_id,"source_digest":current["source_digest"],
        "verified_by":"guided-evidence-verifier","course_verdict":"PASS" if all(checks) else "ERR",
        "security_verdict":"PASS" if all(checks) else "ERR","task_completed":all(checks),
        "next_check":"세 사례의 응답·호출 수를 확인하세요." if all(checks) else "RAW 응답에서 실패한 사례의 함수 오류·호출 수를 확인하세요.",
        "result":{"model_id":MODEL,"provider_request_id":response.get("ResponseMetadata",{}).get("RequestId"),
        "usage":response.get("usage"),"requested_max_output_tokens":64,"forwarded_parameters":{"maxTokens":64},"cases":[{"case_id":c["case_id"],"case_verified":bool(ok),
        "status":"PASS" if ok else "ERR","input":c.get("input"),"expected":{"normal":{"provider_attempts":1,"return":"actual Converse response"},"blank":{"provider_attempts":0,"error_type":"ValueError"},"provider-error":{"provider_attempts":1,"error_type":"RuntimeError","message":"model unavailable"}}[c["case_id"]],"response":c["returned"],"error":c["error"],"provider_attempts":c["provider_attempts"]} for c,ok in zip(cases,checks)]}}
