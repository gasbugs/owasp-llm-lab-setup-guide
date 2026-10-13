"""Check the verifier's pinned provided scaffolds without importing learner code."""
from pathlib import Path
import hashlib
import re
ROOT=Path(__file__).resolve().parents[1]
SPECS={'H05': ('h05-nemo-dialog', ['Containerfile', 'config/config.yml', 'server.py']), 'H06': ('h06-nemo-action', ['Containerfile', 'config/config.yml', 'config/flows.co', 'server.py']), 'H07': ('h07-content-safety', ['Containerfile', 'config/prompts.yml', 'server.py']), 'H08': ('h08-self-check-input', ['Containerfile', 'config/config.yml', 'server.py']), 'H09': ('h09-presidio-redaction', ['Containerfile', 'requirements.txt', 'server.py']), 'H10': ('h10-self-check-output', ['Containerfile', 'server.py', 'config/config.yml']), 'H11': ('h11-rag-provenance', ['Containerfile', 'server.py']), 'H13': ('h13-promptfoo', ['Containerfile', 'server.mjs', 'transform.cjs'])}

def mismatches(root=ROOT):
    source=(root/'llm-security-control-plane/guided-evidence-verifier/server.py').read_text()
    errors=[]
    for code,(folder,files) in SPECS.items():
        digest=hashlib.sha256()
        for name in files:
            digest.update(name.encode())
            digest.update((root/'llm-security-control-plane/guided-labs'/folder/name).read_bytes())
        match=re.search(code+'_SCAFFOLD_DIGEST = "([a-f0-9]{64})"',source)
        if not match or match[1]!=digest.hexdigest():errors.append(code)
    return errors

if __name__=='__main__':
    errors=mismatches()
    if errors:raise SystemExit('ERR: stale provided-scaffold bindings: '+', '.join(errors))
    print(f'PASS: {len(SPECS)} pinned scaffold bindings match supplied source')
