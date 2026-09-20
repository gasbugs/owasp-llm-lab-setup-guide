"""Run the fixed defensive Gateway suite on a fresh, dedicated local ledger.

Requires examples/runtime-security/compose.yaml at 127.0.0.1:18097.
Does not reset state or stop containers. Refuses a previously used time window.
"""
import json, urllib.request, urllib.error, time, os
from pathlib import Path
root=Path(__file__).resolve().parents[2]/'examples/runtime-security'
env=dict(line.split('=',1) for line in (root/'.state/runtime.env').read_text().splitlines())
base='http://127.0.0.1:18097'
normal={'model':'us.amazon.nova-lite-v1:0','messages':[{'role':'user','content':'LLM 가드레일의 역할을 한 문장으로 설명하세요.'}],'max_tokens':120}
records=[]
def call(name,path,body=None,token=None):
    headers={'Content-Type':'application/json'}
    if token:headers['Authorization']='Bearer '+token
    request=urllib.request.Request(base+path, data=json.dumps(body).encode() if body is not None else None,headers=headers)
    started=time.monotonic()
    try:
        with urllib.request.urlopen(request,timeout=120) as r: status,data=r.status,json.load(r)
    except urllib.error.HTTPError as e: status,data=e.code,json.load(e)
    row={'case':name,'http_status':status,'elapsed_seconds':round(time.monotonic()-started,3),'response':data};records.append(row)
    print(json.dumps(row,ensure_ascii=False))
    return status,data
for token in (env['TEAM_A_TOKEN'], env['TEAM_B_TOKEN']):
    request=urllib.request.Request(base+'/v1/usage',headers={'Authorization':'Bearer '+token})
    with urllib.request.urlopen(request,timeout=10) as response: baseline=json.load(response)
    if baseline['requests'] != 0:
        raise SystemExit('Dedicated Gateway ledger already used in this window; existing state preserved.')
status,data=call('normal-a','/v1/chat/completions',normal,env['TEAM_A_TOKEN']);assert status==200 and data['gateway_policy']['upstream_called']
assert data['choices'][0]['finish_reason']=='stop' and data['usage']['completion_tokens']>0
status,data=call('denied-model','/v1/chat/completions',{**normal,'model':'not-allowed-model'},env['TEAM_A_TOKEN']);assert status==403 and not data['detail']['upstream_called']
status,data=call('missing-credential','/v1/chat/completions',normal);assert status==401
status,data=call('declared-principal','/v1/chat/completions',{**normal,'principal':'team-b'},env['TEAM_A_TOKEN']);assert status==422
status,data=call('normal-a-second','/v1/chat/completions',normal,env['TEAM_A_TOKEN']);assert status==200
assert data['choices'][0]['finish_reason']=='stop' and data['usage']['completion_tokens']>0
status,data=call('request-quota','/v1/chat/completions',normal,env['TEAM_A_TOKEN']);assert status==429 and data['detail']['reason']=='request-quota'
status,data=call('normal-b','/v1/chat/completions',normal,env['TEAM_B_TOKEN']);assert status==200 and data['usage']['completion_tokens']>0
assert data['choices'][0]['finish_reason']=='stop' and data['usage']['completion_tokens']>0
status,data=call('output-quota','/v1/chat/completions',normal,env['TEAM_B_TOKEN']);assert status==429 and data['detail']['reason']=='output-token-quota'
status,data=call('usage-b','/v1/usage',token=env['TEAM_B_TOKEN']);assert status==200 and data['requests']==1 and data['output_reserved']==0
os.umask(0o077)
(root/'.state/runtime-gateway-live.json').write_text(json.dumps(records,ensure_ascii=False,indent=2)+'\n')
