"""P02 learner-owned document preparation function.

Validate the two-field JSON body before calling a service. Build the Markdown
source using the server-issued document_id, store it, then embed the original
body. Service errors must propagate; do not create receipts or course verdicts.
"""


async def prepare_document(body, document_id, services):
    raise NotImplementedError("P02 document preparation is not implemented")
