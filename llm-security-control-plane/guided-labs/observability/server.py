"""Execute P18 requests and learner queries; retain suite receipts."""
import hashlib,hmac,json,logging,os,uuid,threading
from pathlib import Path
import httpx,yaml
from fastapi import FastAPI,Header,HTTPException,Response
from prometheus_client import Counter,CONTENT_TYPE_LATEST,generate_latest
from opentelemetry import trace
from opentelemetry._logs import set_logger_provider
from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk._logs import LoggerProvider,LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

CONTROL=os.environ['GUIDED_CONTROL_OBSERVABILITY_TOKEN'];VERIFY=os.environ['GUIDED_VERIFIER_OBSERVABILITY_TOKEN'];ENDPOINT=os.environ['OTEL_EXPORTER_OTLP_ENDPOINT'].rstrip('/');STATE=Path('/state')
COUNTER=Counter('guided_security_decisions_total','Tenant 03 security decisions',['hands_on','decision'])
ACTIVITIES=frozenset({'H18'})
RESOURCE=Resource.create({'service.name':os.getenv('OTEL_SERVICE_NAME','guided-observability')})
tp=TracerProvider(resource=RESOURCE);tp.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=f'{ENDPOINT}/v1/traces')));trace.set_tracer_provider(tp);TRACER=trace.get_tracer('guided-course')
lp=LoggerProvider(resource=RESOURCE);lp.add_log_record_processor(BatchLogRecordProcessor(OTLPLogExporter(endpoint=f'{ENDPOINT}/v1/logs')));set_logger_provider(lp);LOGGER=logging.getLogger('guided-security');LOGGER.setLevel(logging.INFO);LOGGER.addHandler(LoggingHandler(logger_provider=lp))
app=FastAPI(docs_url=None,redoc_url=None)
P18_LOCK=threading.Lock()
if ACTIVITIES == {'H18'}:
    COUNTER.labels('H18','allow')
    COUNTER.labels('H18','block')
def auth(v,e):
    if not hmac.compare_digest(v or '',f'Bearer {e}'): raise HTTPException(401,'invalid credential')
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
@app.get('/readyz')
def ready(): return {'status':'ready'}
@app.get('/metrics')
def metrics(): return Response(generate_latest(),media_type=CONTENT_TYPE_LATEST)
@app.post('/v1/run/{activity}')
def run(activity:str,body:dict,authorization:str|None=Header(None)):
    auth(authorization,CONTROL)
    if activity not in ACTIVITIES: raise HTTPException(404,'unknown activity')
    if activity == 'H18':
        from request_workflow import run_suite
        if not P18_LOCK.acquire(blocking=False): raise HTTPException(409,'P18 suite is already running')
        try:
            result = run_suite(body,Path('/app/h18.yaml'),TRACER,LOGGER,COUNTER,tp,lp,STATE)
        except FileExistsError:
            raise HTTPException(409,'suite already exists')
        except (httpx.HTTPError,TimeoutError):
            raise HTTPException(503,'P18 product collection is unavailable')
        except (ValueError,KeyError,TypeError):
            raise HTTPException(422,'invalid suite metadata')
        finally:
            P18_LOCK.release()
        Path(f"/state/H18-{result['suite_id']}.json").write_text(json.dumps(result),encoding='utf-8')
        return result
@app.get('/v1/receipts/{activity}/{suite}')
def receipt(activity:str,suite:str,authorization:str|None=Header(None)):
    auth(authorization,VERIFY)
    if activity not in ACTIVITIES: raise HTTPException(404,'unknown activity')
    return json.loads(Path(f'/state/{activity}-{suite}.json').read_text())

@app.get('/v1/h18/ledger/{suite}')
def h18_ledger(suite:str,authorization:str|None=Header(None)):
    auth(authorization,VERIFY)
    if 'H18' not in ACTIVITIES: raise HTTPException(404,'unknown activity')
    try:
        canonical=str(uuid.UUID(suite))
    except ValueError:
        raise HTTPException(422,'invalid suite ID')
    path=STATE / f'H18-{canonical}-ledger.json'
    if not path.is_file(): raise HTTPException(404,'ledger not found')
    return json.loads(path.read_text())

@app.get('/v1/h18/build-info')
def h18_build_info(authorization:str|None=Header(None)):
    auth(authorization,VERIFY)
    if 'H18' not in ACTIVITIES: raise HTTPException(404,'unknown activity')
    return {'source_digest':sha('/app/h18.yaml'),'queries':yaml.safe_load(Path('/app/h18.yaml').read_text()),
            'runner_digests':{name:sha(f'/app/{name}') for name in ('server.py','query_execution.py','request_workflow.py')}}
