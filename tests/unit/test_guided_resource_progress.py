"""Progress follows operation boundaries, not elapsed time or fabricated percentages."""
import importlib.util
import ast
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4
import unittest

root=Path(__file__).resolve().parents[2]/'llm-security-control-plane/guided-bedrock-gateway'
spec=importlib.util.spec_from_file_location('resource_progress_test',root/'resource_progress.py')
progress=importlib.util.module_from_spec(spec);spec.loader.exec_module(progress)

class ResourceProgressTests(unittest.TestCase):
    def test_live_steps_and_final_response_boundary(self):
        operation=str(uuid4()); seen=[]
        @progress.tracked('P02')
        def prepare(operation_id):
            progress.step(1); seen.append(progress.read('P02',operation_id))
            progress.step(3); seen.append(progress.read('P02',operation_id))
            progress.step(10); return {'resource_ready':True}
        result=prepare(operation)
        self.assertEqual([(r['current'],r['total']) for r in seen],[(1,11),(3,11)])
        self.assertIn('S3',seen[1]['title'])
        self.assertIn('문서 원문',seen[1]['description'])
        self.assertEqual(result['resource_progress']['current'],10)
        self.assertEqual(result['resource_progress']['state'],'provider_complete')

    def test_failed_step_is_preserved(self):
        operation=str(uuid4())
        @progress.tracked('P03')
        def prepare(operation_id):
            progress.step(7); raise RuntimeError('fixture failure')
        with self.assertRaises(RuntimeError):prepare(operation)
        row=progress.read('P03',operation)
        self.assertEqual(row['current'],7);self.assertEqual(row['state'],'error')
        self.assertIn('Knowledge Base',row['title'])

    def test_other_mission_cannot_read_operation(self):
        operation=str(uuid4())
        @progress.tracked('P04')
        def prepare(operation_id):progress.step(1);return {}
        prepare(operation)
        self.assertEqual(progress.read('P02',operation)['state'],'waiting')

    def test_operation_context_is_thread_local(self):
        @progress.tracked('P02')
        def prepare(operation_id):
            progress.step(3); return {'id':operation_id}
        ids=[str(uuid4()) for _ in range(8)]
        with ThreadPoolExecutor(4) as pool:rows=list(pool.map(prepare,ids))
        self.assertEqual([row['resource_progress']['operation_id'] for row in rows],ids)

    def test_delete_step_total(self):
        @progress.tracked(None,action='delete')
        def delete(problem,operation_id):progress.step(2);return {}
        row=delete('P04',str(uuid4()))['resource_progress']
        self.assertEqual(row['action'],'delete');self.assertEqual(row['total'],4)

    def test_control_totals_match_real_gateway_steps(self):
        source=(root.parent/'guided-control-center/server.py').read_text()
        tree=ast.parse(source)
        node=next(node for node in tree.body if isinstance(node,ast.Assign) and any(
            isinstance(target,ast.Name) and target.id=='RESOURCE_TOTAL_STEPS' for target in node.targets))
        totals=ast.literal_eval(node.value)
        for (problem,action),plan in progress.PLANS.items():
            self.assertEqual(totals[problem][action],len(plan)+1)

    def test_untracked_sdk_fixture_is_unchanged(self):progress.step(1)

if __name__=='__main__':unittest.main()
