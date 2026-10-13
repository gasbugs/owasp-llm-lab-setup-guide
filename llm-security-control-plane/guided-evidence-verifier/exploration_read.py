"""Read product-native execution records without computing a course verdict."""
from uuid import UUID
import httpx
from fastapi import HTTPException

async def read_records(problem, execution, config):
    number = int(problem[1:]) if problem.startswith("P") and problem[1:].isdigit() else 0
    if not 5 <= number <= 22:
        raise HTTPException(404, "Unsupported exploration record")
    if number <= 16:
        url, token = config[f"LAB{number:02d}_URL"], config[f"LAB{number:02d}_TOKEN"]
    elif number <= 20:
        url, token = config[f"H{number}_URL"], config[f"H{number}_TOKEN"]
    else:
        url, token = config[f"H{number}_HOST_URL"], config[f"H{number}_TOKEN"]
    paths = []
    if number == 5:
        for item in execution.get("cases", []):
            identifier = str(UUID(item["execution_id"]))
            paths.append("/v1/receipts/" + identifier)
        evaluation = execution.get("evaluation", {}).get("evaluation_id")
        if not isinstance(evaluation, str) or not evaluation.startswith("nemo-topical-") or not evaluation.removeprefix("nemo-topical-").isalnum():
            raise HTTPException(502, "Missing topical evaluation")
        paths.append("/v1/evaluations/" + evaluation)
    else:
        try:
            identifier = str(UUID(execution["suite_id"]))
        except (ValueError, KeyError, TypeError):
            raise HTTPException(502, "Missing execution identity") from None
        prefix = "/v1/artifacts/" if number in {13, 14, 15} else "/v1/receipts/"
        if 17 <= number <= 20:
            prefix += f"H{number}/"
        paths.append(prefix + identifier)
    records = []
    async with httpx.AsyncClient(timeout=20, trust_env=False, follow_redirects=False) as client:
        for path in paths:
            response = await client.get(url + path, headers={"Authorization": "Bearer " + token})
            if response.status_code != 200:
                raise HTTPException(502, "Runtime record unavailable")
            records.append(response.json())
    return {"activity_id": problem, "records": records}
