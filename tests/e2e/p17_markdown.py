"""Extract P17 solution bytes without running Markdown shell commands."""
import re


def extract_solution(document):
    parts = re.split(r'^## \d+\. 풀이.*$', document, flags=re.MULTILINE)
    if len(parts) != 2:
        raise ValueError('one numbered solution section is required')
    blocks = re.findall(
        r"^cat > llm-security-control-plane/guided-labs/h17-telemetry/instrumentation.py <<'EOF'\n(.*?)^EOF$",
        parts[1], re.MULTILINE | re.DOTALL)
    if len(blocks) != 1:
        raise ValueError('one complete instrumentation.py heredoc is required')
    return blocks[0]
