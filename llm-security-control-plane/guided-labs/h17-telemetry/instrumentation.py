"""P17 learner artifact: instrument the provided business operation."""


def observe_request(request_id, run_business, tracer, logger, counter):
    """Return the unchanged business result after producing its real signals.

    Run business once inside a root span. Supply a stage(name) context manager
    that creates ordered child spans. Record one structured decision log and
    increment one decision counter. Do not put request IDs in metric labels.
    """
    raise NotImplementedError('Implement request Log, Trace and Counter instrumentation')
