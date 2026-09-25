"""Publisher alternative: structured early exit, real service calls, no stage array."""
import json


class StopRequest(Exception):
    def __init__(self, status):
        self.status = status


def require(allowed, status=403):
    if not allowed:
        raise StopRequest(status)


async def handle_request(request, services):
    try:
        require(await services.authenticate(request["credential"]), 401)
        require(await services.authorize(request["tenant"]))
        question = await services.privacy("input_privacy", request["message"])
        require(await services.rail("input_rail", question))
        documents = await services.retrieve(question)
        require(bool(documents), 404)
        require(await services.rail("retrieval_rail", documents))
        prompt = {"context": documents, "question": question}
        generated = await services.main(json.dumps(prompt, ensure_ascii=True, indent=2))
        require(await services.rail("output_rail", generated))
        cleaned = await services.privacy("output_privacy", generated)
        return dict(status=200, text=cleaned)
    except StopRequest as stopped:
        return dict(status=stopped.status, text="")
