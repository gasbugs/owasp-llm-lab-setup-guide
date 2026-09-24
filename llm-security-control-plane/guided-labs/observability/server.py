"""Generate H17-H20 namespaced signals and retain immutable suite receipts."""
import hashlib,hmac,importlib.util,json,logging,os,time,uuid
from datetime import datetime,timezone
from pathlib import Path
import httpx,yaml
from fastapi import FastAPI,Header,HTTPException,Response
from prometheus_client import Counter,Gauge,CONTENT_TYPE_LATEST,generate_latest
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
H20_ACTIVE=Gauge('guided_h20_risk_active','Whether the H20 risk fixture is active')
RESOURCE=Resource.create({'service.name':'guided-observability'})
tp=TracerProvider(resource=RESOURCE);tp.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=f'{ENDPOINT}/v1/traces')));trace.set_tracer_provider(tp);TRACER=trace.get_tracer('guided-course')
lp=LoggerProvider(resource=RESOURCE);lp.add_log_record_processor(BatchLogRecordProcessor(OTLPLogExporter(endpoint=f'{ENDPOINT}/v1/logs')));set_logger_provider(lp);LOGGER=logging.getLogger('guided-security');LOGGER.setLevel(logging.INFO);LOGGER.addHandler(LoggingHandler(logger_provider=lp))
app=FastAPI(docs_url=None,redoc_url=None)
def auth(v,e):
    if not hmac.compare_digest(v or '',f'Bearer {e}'): raise HTTPException(401,'invalid credential')
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def load_py(path,name): s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
@app.get('/readyz')
def ready(): return {'status':'ready'}
@app.get('/metrics')
def metrics(): return Response(generate_latest(),media_type=CONTENT_TYPE_LATEST)
@app.post('/v1/run/{activity}')
def run(activity:str,body:dict,authorization:str|None=Header(None)):
    auth(authorization,CONTROL)
    if activity not in {'H17','H18','H19','H20'}: raise HTTPException(404,'unknown activity')
    suite=body['suite_id']; request_id=str(uuid.uuid4()); do_export=activity!='H17' or load_py('/app/h17.py','h17').EXPORT_TO_ALLOY
    with TRACER.start_as_current_span('security.request',attributes={'hands_on':activity,'request_id':request_id,'decision':'block'}) as span:
        trace_id=f'{span.get_span_context().trace_id:032x}'
        if do_export:
            with TRACER.start_as_current_span('input_rail',attributes={'request_id':request_id,'policy_rule':'indirect-prompt-injection'}): pass
            LOGGER.warning('security_decision',extra={'hands_on':activity,'request_id':request_id,'trace_id':trace_id,'decision':'block','policy_rule':'indirect-prompt-injection'})
    COUNTER.labels(activity,'block').inc(); tp.force_flush(); lp.force_flush(); time.sleep(2)
    receipt={'suite_id':suite,'started_at':body['started_at'],'observed_at':datetime.now(timezone.utc).isoformat(),'activity':activity,'request_id':request_id,'trace_id':trace_id,'decision':'block','policy_rule':'indirect-prompt-injection','main_called':False,'export_enabled':do_export}
    if activity=='H17': receipt|={'source_digest':sha('/app/h17.py')}
    if activity=='H18': receipt|={'queries':yaml.safe_load(Path('/app/h18.yaml').read_text()),'source_digest':sha('/app/h18.yaml')}
    if activity=='H19': receipt|={'join_key':load_py('/app/h19.py','h19').JOIN_KEY,'source_digest':sha('/app/h19.py'),'stages':['authenticate','authorize','retrieval','input_rail']}
    if activity=='H20':
        H20_ACTIVE.set(1); time.sleep(7)
        firing=httpx.get('http://prometheus:9090/api/v1/alerts',timeout=5).json()
        H20_ACTIVE.set(0); time.sleep(7)
        resolved=httpx.get('http://prometheus:9090/api/v1/alerts',timeout=5).json()
        receipt|={'dashboard_query':Path('/app/h20.txt').read_text().strip(),'source_digest':sha('/app/h20.txt'),'firing_snapshot':firing,'resolved_snapshot':resolved}
    Path(f'/state/{activity}-{suite}.json').write_text(json.dumps(receipt),encoding='utf-8');return receipt
@app.get('/v1/receipts/{activity}/{suite}')
def receipt(activity:str,suite:str,authorization:str|None=Header(None)):
    auth(authorization,VERIFY);return json.loads(Path(f'/state/{activity}-{suite}.json').read_text())
