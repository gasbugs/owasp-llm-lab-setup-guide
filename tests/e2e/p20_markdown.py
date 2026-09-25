"""Extract complete P20 solution files without executing Markdown shell."""
import re


def extract_solution(document):
    parts = re.split(r'^## \d+\. 풀이.*$', document, flags=re.MULTILINE)
    if len(parts) != 2:
        raise ValueError('one numbered solution section is required')
    files = {}
    for name in ('rules.yaml', 'dashboard.json'):
        prefix = 'cat > llm-security-control-plane/guided-labs/h20-alert-dashboard/' + name + " <<'EOF'"
        matches = re.findall('^' + re.escape(prefix) + r'\n(.*?)^EOF$',
                             parts[1], flags=re.MULTILINE | re.DOTALL)
        if len(matches) != 1:
            raise ValueError('one complete solution heredoc required: ' + name)
        files[name] = matches[0]
    return files
