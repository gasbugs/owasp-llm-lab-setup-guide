module.exports = (json) => {
  const guardrail = json.guardrail || {};
  return JSON.stringify({
    application_decision: json.application_decision || null,
    upstream_called: json.upstream_called === true,
    blocking_reason: json.blocking_reason || null,
    assurance_profile: guardrail.assurance_profile || null,
    guard_model_calls: guardrail.guard_model_calls ?? null,
    stage_order: guardrail.stage_order || [],
  });
};
