"""Publisher-only implementation fixture; never copied into the learner Starter."""
import json


async def handle_request(request, services):
    if not await services.authenticate(request["credential"]):
        return {"status": 401, "text": ""}
    if not await services.authorize(request["tenant"]):
        return {"status": 403, "text": ""}
    message = await services.privacy("input_privacy", request["message"])
    if not await services.rail("input_rail", message):
        return {"status": 403, "text": ""}
    context = await services.retrieve(message)
    if not context:
        return {"status": 404, "text": ""}
    if not await services.rail("retrieval_rail", context):
        return {"status": 403, "text": ""}
    answer = await services.main(json.dumps({"question": message, "context": context}, ensure_ascii=False))
    if not await services.rail("output_rail", answer):
        return {"status": 403, "text": ""}
    return {"status": 200, "text": await services.privacy("output_privacy", answer)}
