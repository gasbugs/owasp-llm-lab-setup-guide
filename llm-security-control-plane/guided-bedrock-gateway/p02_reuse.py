"""Read-only checks before reusing P02 storage and role configuration."""
from fastapi import HTTPException
from botocore.exceptions import ClientError


TAGS = {"Course": "tenant-03", "Activity": "H02", "ManagedBy": "guided-control-center"}
PUBLIC_BLOCK = dict.fromkeys(("BlockPublicAcls", "IgnorePublicAcls",
                             "BlockPublicPolicy", "RestrictPublicBuckets"), True)


def require(condition, resource):
    if not condition:
        raise HTTPException(409, f"existing P02 {resource} differs; no automatic repair")


def check_bucket(s3, template):
    args = {"Bucket": template["source_bucket"], "ExpectedBucketOwner": template["account_id"]}
    tags = s3.get_bucket_tagging(**args)["TagSet"]
    require({item["Key"]: item["Value"] for item in tags} == TAGS, "bucket tags")
    config = s3.get_public_access_block(**args)["PublicAccessBlockConfiguration"]
    require(config == PUBLIC_BLOCK, "bucket public access block")


def check_role(iam, template, role, policy_name):
    require(role.get("Arn") == template["role_arn"], "role ARN")
    require(role.get("AssumeRolePolicyDocument") == template["trust_policy"], "role trust")
    require({item["Key"]: item["Value"] for item in role.get("Tags", [])} == TAGS, "role tags")
    require("PermissionsBoundary" not in role, "role permissions boundary")
    args = {"RoleName": template["role_name"]}
    policies = iam.list_role_policies(**args)
    require(not policies.get("IsTruncated") and policies.get("PolicyNames") == [policy_name], "inline policies")
    attached = iam.list_attached_role_policies(**args)
    require(not attached.get("IsTruncated") and attached.get("AttachedPolicies") == [], "attached policies")
    policy = iam.get_role_policy(**args, PolicyName=policy_name)
    require(policy.get("PolicyDocument") == template["runtime_policy"], "runtime policy")


def optional(fetch, absent_codes):
    try:
        return fetch()
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") in absent_codes:
            return None
        raise


def pages(fetch, field, **kwargs):
    result, seen = [], set()
    for _ in range(100):
        response = fetch(**kwargs)
        result.extend(response[field])
        token = response.get("nextToken")
        if not token:
            return result
        require(token not in seen, "pagination")
        seen.add(token)
        kwargs["nextToken"] = token
    require(False, "pagination limit")


def preflight(template, *, s3, vectors, iam, agent, policy_name, allow_partial=False):
    """Return reusable state. Explicit preparation may also accept audited gaps.

    The default remains strict for read-only reuse and publisher cleanup audits.
    None with allow_partial means missing resources may be created, not replaced.
    """
    from p02_resources import connection_evidence
    from p02_ledger import LedgerError

    source = optional(lambda: s3.head_bucket(
        Bucket=template["source_bucket"], ExpectedBucketOwner=template["account_id"]), {"404", "NoSuchBucket"})
    vector = optional(lambda: vectors.get_vector_bucket(
        vectorBucketName=template["vector_bucket"]), {"NotFoundException"})
    role = optional(lambda: iam.get_role(RoleName=template["role_name"]), {"NoSuchEntity"})
    matches = [item for item in pages(agent.list_knowledge_bases, "knowledgeBaseSummaries", maxResults=100)
               if item.get("name") == template["knowledge_base_name"]]
    present = (source is not None, vector is not None, role is not None, bool(matches))
    if not any(present):
        return None
    require(len(matches) <= 1 and (allow_partial or all(present)), "partial or duplicate resource set")
    require(not allow_partial or source is not None or role is not None or matches,
            "ownership tags unavailable; inspect the surviving vector bucket")
    missing = not all(present)
    if source is not None:
        check_bucket(s3, template)
    if role is not None:
        check_role(iam, template, role["Role"], policy_name)
    if vector is not None:
        require(vector["vectorBucket"]["vectorBucketArn"] == template["vector_bucket_arn"], "vector bucket")
    if allow_partial:
        index = optional(lambda: vectors.get_index(indexArn=template["index_arn"]), {"NotFoundException"}) if vector else None
        if index is None:
            missing = True
        else:
            require(all(index["index"].get(key) == value for key, value in {
                "indexArn": template["index_arn"], "dimension": 1024,
                "dataType": "float32", "distanceMetric": "cosine"}.items()), "vector index")
    if not matches:
        return None
    kb_id = matches[0]["knowledgeBaseId"]
    kb = agent.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"]
    require(kb.get("name") == template["knowledge_base_name"] and kb.get("roleArn") == template["role_arn"], "knowledge base")
    require(agent.list_tags_for_resource(resourceArn=kb["knowledgeBaseArn"])["tags"] == TAGS, "knowledge base tags")
    if allow_partial:
        require(kb.get("knowledgeBaseId") == kb_id and kb.get("status") == "ACTIVE", "knowledge base status")
        require(kb.get("knowledgeBaseConfiguration") == {"type": "VECTOR", "vectorKnowledgeBaseConfiguration": {
            "embeddingModelArn": f"arn:aws:bedrock:{template['region']}::foundation-model/{template['embedding_model_id']}",
            "embeddingModelConfiguration": {"bedrockEmbeddingModelConfiguration": {
                "dimensions": 1024, "embeddingDataType": "FLOAT32"}}}}, "embedding configuration")
        require(kb.get("storageConfiguration") == {"type": "S3_VECTORS",
                "s3VectorsConfiguration": {"indexArn": template["index_arn"]}}, "storage configuration")
    sources = pages(agent.list_data_sources, "dataSourceSummaries", knowledgeBaseId=kb_id, maxResults=100)
    if allow_partial and not sources:
        return None
    require(len(sources) == 1 and sources[0].get("name") == template["data_source_name"], "data sources")
    ds_id = sources[0]["dataSourceId"]
    ds = agent.get_data_source(knowledgeBaseId=kb_id, dataSourceId=ds_id)["dataSource"]
    require(ds.get("name") == template["data_source_name"] and ds.get("dataDeletionPolicy") == "DELETE", "data source policy")
    require(ds.get("vectorIngestionConfiguration") == {"chunkingConfiguration": {
        "chunkingStrategy": "FIXED_SIZE", "fixedSizeChunkingConfiguration": {"maxTokens": 200, "overlapPercentage": 20}}}, "chunking")
    if allow_partial:
        require(ds.get("knowledgeBaseId") == kb_id and ds.get("dataSourceId") == ds_id
                and ds.get("status") == "AVAILABLE", "data source status")
        require(ds.get("dataSourceConfiguration") == {"type": "S3", "s3Configuration": {
            "bucketArn": f"arn:aws:s3:::{template['source_bucket']}", "bucketOwnerAccountId": template["account_id"],
            "inclusionPrefixes": [template["source_prefix"]]}}, "source configuration")
    if missing:
        return None
    state = {key: template[key] for key in (
        "account_id", "region", "template_digest", "source_bucket", "source_prefix",
        "vector_bucket", "index_arn", "embedding_model_id", "dimensions")}
    state.update(status="READY", provider_mode="aws", knowledge_base_id=kb_id, data_source_id=ds_id)
    clients = {"s3": s3, "s3vectors": vectors, "bedrock-agent": agent}
    try:
        evidence = connection_evidence(state, client_factory=clients.__getitem__, mode="aws")
    except LedgerError:
        raise HTTPException(502, "existing P02 resource connection could not be verified") from None
    state["aws_request_ids"] = evidence["resource_request_ids"]
    return state
