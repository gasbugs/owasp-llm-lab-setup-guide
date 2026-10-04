"""Run the real AWS reconciliation script with deterministic service responses."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

CONTROL = Path(__file__).resolve().parents[2] / 'llm-security-control-plane'
AWS = r'''#!/usr/bin/env python3
import json, os, sys
args=sys.argv[1:]
with open(os.environ['KB_CALLS'],'a') as f: f.write(json.dumps(args)+'\n')
mode=os.environ['KB_CASE']
op=args[1] if len(args)>1 else ''
if mode=='denied' and op=='list-knowledge-bases': sys.exit(9)
if mode=='missing' and op in ('head-bucket','get-vector-bucket','get-index','get-role'): sys.exit(4)
values={'get-caller-identity':'123456789012','list-knowledge-bases':'None' if mode=='missing' else 'AUTO123456',
'get-knowledge-base':'ACTIVE','list-data-sources':'None' if mode=='missing' else 'SOURCE1234',
'get-data-source':'AVAILABLE','list-ingestion-jobs':'COMPLETE','create-knowledge-base':'AUTO123456',
'create-data-source':'SOURCE1234','start-ingestion-job':'INGEST1234','get-ingestion-job':'COMPLETE'}
print(values.get(op,''))
'''

class EnsureEvaluationKnowledgeTests(unittest.TestCase):
    def run_case(self, case):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'control'
            shutil.copytree(CONTROL/'deploy',root/'deploy')
            shutil.copytree(CONTROL/'aws',root/'aws')
            bin_dir=Path(tmp)/'bin'; bin_dir.mkdir()
            for name,content in [('aws',AWS),('sleep','#!/bin/sh\nexit 0\n')]:
                p=bin_dir/name;p.write_text(content);p.chmod(0o755)
            log=Path(tmp)/'calls'
            state=Path(tmp)/'isolated-state'
            env=os.environ|{'PATH':str(bin_dir)+':'+os.environ['PATH'],'KB_CALLS':str(log),
                'KB_CASE':case,'MODULE08_AWS_STATE_DIR':str(state)}
            result=subprocess.run(['bash',str(root/'deploy/restore-module08-aws.sh'),'--ensure'],
                env=env,text=True,capture_output=True)
            calls=[json.loads(x) for x in log.read_text().splitlines()]
            return result,calls,(state/'module08-aws.env').read_text() if (state/'module08-aws.env').exists() else ''

    def test_ready_resource_is_reused_without_writes(self):
        result,calls,state=self.run_case('ready')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('module08-aws=READY',result.stdout)
        self.assertIn('MODULE08_KNOWLEDGE_BASE_ID=AUTO123456',state)
        self.assertTrue(all(c[0] in ('sts','bedrock-agent') and c[1].startswith(('get-','list-')) for c in calls))

    def test_missing_resource_creates_storage_role_and_ingests_documents(self):
        result,calls,state=self.run_case('missing')
        self.assertEqual(result.returncode,0,result.stderr)
        ops=[c[1] for c in calls]
        self.assertIn('create-knowledge-base',ops)
        self.assertIn('create-data-source',ops)
        self.assertIn('start-ingestion-job',ops)
        for op in ('create-bucket','create-vector-bucket','create-index','create-role','put-role-policy'):
            self.assertIn(op,ops)
        self.assertIn('MODULE08_KNOWLEDGE_BASE_ID=AUTO123456',state)
        self.assertIn('module08-aws=RESTORED',result.stdout)

    def test_discovery_api_error_is_not_treated_as_absence(self):
        result,calls,state=self.run_case('denied')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(state,'')
        self.assertFalse(any(c[1].startswith(('create-','delete-','put-')) for c in calls))
