"""Publisher-only implementation; never copied into the learner Starter image."""


async def search_current(current_job_id, services):
    observed = await services.job_status()
    if observed.get("ingestion_job_id") != current_job_id:
        raise ValueError("different job")
    status = observed.get("status")
    if status in ("QUEUED", "STARTING", "IN_PROGRESS"):
        return {"status": "waiting", "result": None}
    if status != "COMPLETE":
        raise ValueError("unusable status")
    return {"status": "ready", "result": await services.retrieve()}
