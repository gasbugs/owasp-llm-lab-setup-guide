import hmac,os,uuid
from fastapi import FastAPI,Header,HTTPException
from pydantic import BaseModel
app=FastAPI(docs_url=None,redoc_url=None); TOKEN=os.environ['GUIDED_H15_TARGET_TOKEN']
class Input(BaseModel): message:str; conversation_id:str
@app.get('/readyz')
def ready(): return {'status':'ready'}
@app.post('/api/chat')
def chat(value:Input,authorization:str|None=Header(None)):
    if not hmac.compare_digest(authorization or '',f'Bearer {TOKEN}'): raise HTTPException(401,'invalid credential')
    risk='H15_POLICY_BYPASS_CANARY' in value.message
    return {'request_id':str(uuid.uuid4()),'decision':'block' if risk else 'allow','upstream_called':not risk,'reply':'요청을 처리할 수 없습니다.' if risk else '정책은 안전한 사용을 돕습니다.'}
