module.exports = (json) => {
  const outer = json.guardrail || {};
  const inner = outer.inner_guardrail || {};
  const effectiveDecision = inner.decision === 'block' ? 'block' : outer.decision;
  const upstreamCalled = inner.decision === 'block'
    ? inner.upstream_called === true
    : outer.upstream_called === true;
  const firstInputCheck = Array.isArray(outer.input_checks) ? outer.input_checks[0] || {} : {};

  return JSON.stringify({
    reply: json.reply || '',
    effective_decision: effectiveDecision,
    outer_decision: outer.decision || null,
    inner_decision: inner.decision || null,
    upstream_called: upstreamCalled,
    blocking_reason: inner.blocking_reason || outer.blocking_reason || null,
    input_entities: firstInputCheck.entity_types || [],
    policy_version: outer.policy_version || null,
  });
};
