import hmac, os, uuid
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
app=FastAPI(docs_url=None,redoc_url=None); TOKEN=os.environ["GUIDED_H14_TARGET_TOKEN"]
class Input(BaseModel): message:str
@app.get('/readyz')
def ready(): return {'status':'ready'}
@app.post('/api/chat')
def chat(value:Input,authorization:str|None=Header(None)):
    if not hmac.compare_digest(authorization or '',f'Bearer {TOKEN}'): raise HTTPException(401,'invalid credential')
    return {'request_id':str(uuid.uuid4()),'reply':'요청을 안전하게 처리했습니다.','impact_marker':False}
