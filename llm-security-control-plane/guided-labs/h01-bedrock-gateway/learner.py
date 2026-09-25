"""P01 learner artifact: validate a chat request, then call Bedrock Converse."""


def handle_request(body: dict, client) -> dict:
    """Return the raw Converse response; raise ValueError for an invalid body.

    body contains only the client request, not grading metadata or credentials.
    client.converse(**kwargs) has the Boto3 Converse interface.
    Implement validation, request limits, and the actual invocation here.
    """
    raise NotImplementedError("P01 request handling is not implemented")
