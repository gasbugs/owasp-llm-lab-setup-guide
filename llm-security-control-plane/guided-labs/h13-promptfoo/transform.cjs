module.exports = (data) => JSON.stringify({
  request_id: data.request_id,
  decision: data.decision,
  policy_rule: data.policy_rule,
  upstream_called: data.upstream_called,
  answer: data.answer,
});
