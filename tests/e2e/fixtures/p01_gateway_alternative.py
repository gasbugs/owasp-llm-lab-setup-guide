"""Independent contract implementation, excluded from learner images."""


def handle_request(body, client):
    if sorted(body) != ['max_output_tokens', 'message']:
        raise ValueError('fields')
    text = body['message']
    limit = body['max_output_tokens']
    accepted_text = isinstance(text, str) and 0 < len(text) <= 4000 and bool(text.strip())
    accepted_limit = type(limit) is int and limit in range(1, 513)
    if not (accepted_text and accepted_limit):
        raise ValueError('input')
    actual_limit = limit if limit <= 128 else 128
    arguments = dict(
        modelId='us.amazon.nova-lite-v1:0',
        inferenceConfig=dict(temperature=0.0, maxTokens=actual_limit),
        messages=[dict(role='user', content=[dict(text=text)])],
    )
    reservation = client.reserve_budget(actual_limit)
    try:
        response = client.converse(**arguments)
    except Exception:
        client.cancel_budget(reservation)
        raise
    client.settle_budget(reservation, response['usage']['outputTokens'])
    return response
