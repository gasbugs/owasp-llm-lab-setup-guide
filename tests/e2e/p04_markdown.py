"""Extract the P04 solution as data; never execute document shell commands."""
import ast
import re


def extract_solution(document):
    parts = re.split(r'^## \d+\. 풀이(?:\s|:|$).*$', document, flags=re.MULTILINE)
    if len(parts) != 2:
        raise ValueError('one numbered solution section is required')
    blocks = re.findall(
        r"^cat > llm-security-control-plane/guided-labs/h04-bedrock-guardrail/learner.py <<'EOF'\n(.*?)^EOF$",
        parts[1], re.MULTILINE | re.DOTALL)
    if len(blocks) != 1:
        raise ValueError('one complete learner.py heredoc is required')
    source = blocks[0]
    if len(source.encode('utf-8')) > 65536:
        raise ValueError('solution exceeds learner source limit')
    try:
        tree = ast.parse(source)
    except SyntaxError as error:
        raise ValueError('solution is not valid Python') from error
    functions = [node for node in tree.body if isinstance(node, ast.AsyncFunctionDef)
                 and node.name == 'invoke_guarded']
    if len(functions) != 1:
        raise ValueError('one async invoke_guarded function is required')
    return source
