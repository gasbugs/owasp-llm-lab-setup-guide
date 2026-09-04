module.exports = (json) => {
  const guardrail = json.guardrail || {};
  return JSON.stringify({
    application_decision: json.application_decision || null,
    upstream_called: json.upstream_called === true,
    blocking_reason: json.blocking_reason || null,
    request_id: json.request_id || null,
    trace_id: json.trace_id || null,
    assurance_profile: guardrail.assurance_profile || null,
    guard_model_calls: guardrail.guard_model_calls ?? null,
    stage_order: guardrail.stage_order || [],
    policy_id: guardrail.policy_id || null,
    policy_bundle_version: guardrail.policy_bundle_version || null,
  });
};
