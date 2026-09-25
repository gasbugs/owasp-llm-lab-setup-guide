"""P04-owned EMAIL policy and read-only AWS reuse audit.

No update/delete operations are provided. Matching a name is not sufficient for
reuse: account, ARN, ownership tags and the complete policy must match.
SDK schema: https://docs.aws.amazon.com/boto3/latest/reference/services/bedrock/client/get_guardrail.html
"""
from copy import deepcopy
import hashlib
import re
import time

from p04_contract import canonical
from p04_ledger import LedgerError
from p04_suites import resource_snapshot


def template(account_id, region="us-east-1"):
    if not isinstance(account_id, str) or not re.fullmatch(r"[0-9]{12}", account_id) or region != "us-east-1":
        raise ValueError("P04 requires the current AWS account and course region")
    policy = {
        "sensitiveInformationPolicyConfig": {"piiEntitiesConfig": [{
            "type": "EMAIL", "action": "ANONYMIZE", "inputAction": "NONE",
            "outputAction": "ANONYMIZE", "inputEnabled": False, "outputEnabled": True}]},
        "blockedInputMessaging": "요청이 관리형 정책에 의해 차단되었습니다.",
        "blockedOutputsMessaging": "응답이 관리형 정책에 의해 처리되었습니다.",
    }
    result = {"account_id": account_id, "region": region,
              "name": "owasp-guided-p04-" + account_id,
              "description": "Tenant 03 P04 output EMAIL guardrail",
              "tags": {"Course": "tenant-03", "Activity": "P04", "ManagedBy": "guided-control-center"},
              "policy": policy}
    result["template_digest"] = hashlib.sha256(canonical(result)).hexdigest()
    return result


def require(condition):
    if not condition:
        raise LedgerError(409)


def validate_owned(specification, detail, tags, *, expected_id):
    """Pure audit of GET responses; these values are never supplied by a learner."""
    try:
        t = deepcopy(specification)
        require(canonical(t) == canonical(template(t["account_id"], t["region"])))
        require(isinstance(expected_id, str) and re.fullmatch(r"[a-z0-9]{1,64}", expected_id))
        arn = f"arn:aws:bedrock:{t['region']}:{t['account_id']}:guardrail/{expected_id}"
        require(isinstance(detail, dict) and set(detail) <= {
            "name", "description", "guardrailId", "guardrailArn", "version", "status",
            "sensitiveInformationPolicy", "blockedInputMessaging", "blockedOutputsMessaging",
            "topicPolicy", "contentPolicy", "wordPolicy", "contextualGroundingPolicy",
            "automatedReasoningPolicy", "crossRegionDetails", "kmsKeyArn", "createdAt", "updatedAt",
            "statusReasons", "failureRecommendations", "ResponseMetadata"})
        require(detail.get("guardrailId") == expected_id and detail.get("guardrailArn") == arn
                and detail.get("name") == t["name"] and detail.get("description") == t["description"]
                and detail.get("version") == "DRAFT" and detail.get("status") == "READY")
        sensitive = detail["sensitiveInformationPolicy"]
        expected = t["policy"]["sensitiveInformationPolicyConfig"]["piiEntitiesConfig"]
        require(isinstance(sensitive, dict) and set(sensitive) <= {"piiEntities", "regexes"}
                and canonical(sensitive.get("piiEntities")) == canonical(expected)
                and sensitive.get("regexes", []) == [])
        for field in ("blockedInputMessaging", "blockedOutputsMessaging"):
            require(detail.get(field) == t["policy"][field])
        empty_shapes = {"topicPolicy": {"topics": []}, "contentPolicy": {"filters": []},
                        "wordPolicy": {"words": [], "managedWordLists": []},
                        "contextualGroundingPolicy": {"filters": []},
                        "automatedReasoningPolicy": {"policies": []}}
        for field, empty in empty_shapes.items():
            value = detail.get(field, {})
            require(isinstance(value, dict) and set(value) <= set(empty)
                    and all(value[key] == empty[key] for key in value))
        require(detail.get("crossRegionDetails", {}) == {} and detail.get("kmsKeyArn") is None)
        require(detail.get("statusReasons", []) == [] and detail.get("failureRecommendations", []) == [])
        require(isinstance(tags, list) and len(tags) <= 200)
        owners = {}
        for tag in tags:
            require(isinstance(tag, dict) and set(tag) == {"key", "value"}
                    and isinstance(tag["key"], str) and isinstance(tag["value"], str)
                    and tag["key"] not in owners)
            owners[tag["key"]] = tag["value"]
        require(all(owners.get(key) == value for key, value in t["tags"].items()))
        return resource_snapshot({"provider_mode": "aws", "guardrail": {
            "guardrailIdentifier": expected_id, "guardrailVersion": "DRAFT"},
            "guardrail_arn": arn, "policy_digest": t["template_digest"]})
    except (ValueError, KeyError, TypeError, AttributeError):
        raise LedgerError(409) from None


def inspect_existing(specification, *, client, clock=time.monotonic):
    """Return an audited resource or an explicit absent result, never repair it."""
    try:
        t = deepcopy(specification)
        require(canonical(t) == canonical(template(t["account_id"], t["region"]))
                and client.meta.region_name == t["region"])
        deadline = clock() + 60
        request_ids = []

        def call(method, **kwargs):
            require(clock() < deadline)
            result = method(**kwargs)
            require(clock() < deadline and isinstance(result, dict))
            metadata = result["ResponseMetadata"]
            request_id = metadata["RequestId"]
            require(type(metadata["HTTPStatusCode"]) is int and metadata["HTTPStatusCode"] == 200
                    and isinstance(request_id, str) and request_id.isascii() and 1 <= len(request_id) <= 256
                    and request_id not in request_ids)
            request_ids.append(request_id)
            return result

        matches, seen, arguments = [], set(), {"maxResults": 100}
        for _ in range(100):
            page = call(client.list_guardrails, **arguments)
            require(isinstance(page["guardrails"], list))
            for item in page["guardrails"]:
                require(isinstance(item, dict))
                if item.get("name") == t["name"]:
                    matches.append(item)
            token = page.get("nextToken")
            if token is None:
                break
            require(isinstance(token, str) and token and token not in seen)
            seen.add(token)
            arguments["nextToken"] = token
        else:
            raise LedgerError(409)
        require(len(matches) <= 1)
        if not matches:
            return {"state": "absent", "resources": None, "aws_request_ids": request_ids}
        guardrail_id = matches[0]["id"]
        require(isinstance(guardrail_id, str) and re.fullmatch(r"[a-z0-9]{1,64}", guardrail_id))
        arn = f"arn:aws:bedrock:{t['region']}:{t['account_id']}:guardrail/{guardrail_id}"
        require(matches[0].get("arn") == arn and matches[0].get("version") == "DRAFT")
        detail = call(client.get_guardrail, guardrailIdentifier=guardrail_id, guardrailVersion="DRAFT")
        tagged = call(client.list_tags_for_resource, resourceARN=arn)
        snapshot = validate_owned(t, detail, tagged["tags"], expected_id=guardrail_id)
        return {"state": "ready", "resources": snapshot, "aws_request_ids": request_ids}
    except (ValueError, KeyError, TypeError, AttributeError):
        raise LedgerError(409) from None
