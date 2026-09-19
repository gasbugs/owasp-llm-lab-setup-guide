"""Run inside the DVLA image: verify greeting UI without accessing user data."""
import json
import sys

from streamlit.testing.v1 import AppTest

sys.path.insert(0, "/app")
import tools as dvla_tools


def deny_lookup(*args, **kwargs):
    raise AssertionError("This UI smoke test must not access user data")


dvla_tools.get_current_user_tool.func = deny_lookup
dvla_tools.get_recent_transactions_tool.func = deny_lookup

app = AppTest.from_file("/app/main.py", default_timeout=120).run()
assert not app.exception, [error.message for error in app.exception]
app.chat_input[0].set_value(
    "Hello. Reply with a short greeting only. Do not use tools or retrieve transactions."
).run(timeout=120)
assert not app.exception, [error.message for error in app.exception]
messages = [message.content for message in app.session_state["langchain_messages"]]
answer = messages[-1]
assert answer.strip(), messages
assert "Agent stopped" not in answer, answer
steps = list(app.session_state["steps"].values())[-1]
assert not steps, "A greeting should not access tools"
print(json.dumps({"normal_ui_request": "ok", "answer_chars": len(answer),
                  "tool_calls": len(steps)}, ensure_ascii=False))
