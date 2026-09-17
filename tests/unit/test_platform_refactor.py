"""Benign retrieval integration and fail-closed customer grounding regressions."""
from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
from test_llm02_auth_api import load_main_module

MAIN = load_main_module()
ROOT = Path(__file__).resolve().parents[2]


class PlatformRefactorTests(unittest.TestCase):
    def test_shared_navigation_is_synchronized(self):
        subprocess.run([sys.executable, str(ROOT / "tools/sync_platform_ui.py"), "--check"], check=True)

    def test_wrong_planner_customer_is_rejected_before_database(self):
        planner = AsyncMock(return_value={"action": "lookup", "customer_id": "C-9999",
                                         "fields": ["delivery_status"], "reason": "delivery"})
        with patch.object(MAIN.llm, "structured_chat", planner), TestClient(MAIN.app) as client:
            response = client.post('/api/labs/llm02/safe/chat',
                headers={"Authorization": "Bearer llm02-c2001-demo-token"},
                json={"message": "내 배송 상태를 확인해 주세요."})
        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json()['trace']['blocking_reason'], 'customer-target-not-grounded')
        self.assertFalse(response.json()['trace']['customer_query_called'])
        self.assertFalse(response.json()['trace']['answer_model_called'])

    def test_ambiguous_customer_request_never_queries(self):
        planner = AsyncMock(return_value={"action": "lookup", "customer_id": "C-2001",
                                         "fields": ["delivery_status"], "reason": "delivery"})
        with patch.object(MAIN.llm, "structured_chat", planner), TestClient(MAIN.app) as client:
            response = client.post('/api/labs/llm02/safe/chat',
                headers={"Authorization": "Bearer llm02-c2001-demo-token"},
                json={"message": "C-2001과 C-2002 중 배송 상태 확인"})
        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json()['trace']['blocking_reason'], 'customer-target-ambiguous')
        self.assertFalse(response.json()['trace']['customer_query_called'])

    def test_documents_search_context_and_delete_share_current_corpus(self):
        # Deliberately controlled vectors test plumbing, not real model semantics.
        async def embed(texts):
            return [[1., 0.] if index == 0 or 'orchard' in text else [0., 1.]
                    for index, text in enumerate(texts)]
        model = AsyncMock(return_value='검증용 답변')
        with patch.object(MAIN, 'DEFAULT_SCENARIO', 'llm04'), \
             patch.object(MAIN.embedding, 'embed', side_effect=embed), \
             patch.object(MAIN.llm, 'chat', model), TestClient(MAIN.app) as client:
            before = client.get('/api/admin/docs').json()['docs']
            try:
                added = client.post('/api/admin/inject-doc', json={'title': 'Orchard notes', 'text': 'orchard care'})
                self.assertEqual(added.status_code, 200)
                result = client.post('/api/search', json={'query': 'fruit trees', 'top_k': 1, 'min_score': .5})
                self.assertEqual(result.status_code, 200)
                hit = result.json()['hits'][0]
                self.assertEqual(hit['score'], 1.)
                self.assertIn('orchard care', hit['text'])
                model.assert_not_awaited()
                reply = client.post('/api/chat', json={'message': 'fruit trees'}).json()
                self.assertEqual(reply['debug']['retrieved_chunks'][0], hit['text'])
                self.assertIn(hit['text'], model.call_args.kwargs['system'])
            finally:
                client.delete(f'/api/admin/docs/{len(before)}')
            empty = client.post('/api/search', json={'query': 'fruit trees', 'min_score': .5}).json()
            self.assertEqual(empty['hits'], [])

    def test_invalid_embedding_blocks_generation(self):
        model = AsyncMock()
        with patch.object(MAIN, 'DEFAULT_SCENARIO', 'llm04'), \
             patch.object(MAIN.embedding, 'embed', AsyncMock(return_value=[[0., 0.]])), \
             patch.object(MAIN.llm, 'chat', model), TestClient(MAIN.app) as client:
            result = client.post('/api/chat', json={'message': 'Translate hello'})
        self.assertEqual(result.status_code, 502)
        model.assert_not_awaited()

    def test_search_rejects_invalid_parameters(self):
        with TestClient(MAIN.app) as client:
            for body in ({'query': ' '}, {'query': 'hello', 'top_k': 0},
                         {'query': 'hello', 'min_score': 2}):
                self.assertEqual(client.post('/api/search', json=body).status_code, 422)

    def test_tenant_search_authenticates_before_embedding(self):
        embed = AsyncMock()
        with patch.object(MAIN, 'DEFAULT_SCENARIO', 'day4'), \
             patch.object(MAIN.embedding, 'embed', embed), TestClient(MAIN.app) as client:
            result = client.post('/api/search', json={'query': 'quarterly report'})
        self.assertEqual(result.status_code, 401)
        embed.assert_not_awaited()

    def test_tenant_search_prefilters_before_ranking(self):
        async def embed(texts):
            self.assertFalse(any('Beta' in text or 'bsk-' in text for text in texts))
            return [[1., 0.] for _ in texts]
        with patch.object(MAIN, 'DEFAULT_SCENARIO', 'day4'), \
             patch.object(MAIN.embedding, 'embed', side_effect=embed), TestClient(MAIN.app) as client:
            result = client.post('/api/search', json={'query': 'quarterly report'},
                headers={'Authorization': 'Bearer llm08-acme-demo-token'})
        self.assertEqual(result.status_code, 200)
        self.assertTrue(result.json()['filter']['applied'])
        self.assertTrue(all(hit['tenant'] == 'acme' for hit in result.json()['hits']))


if __name__ == '__main__':
    unittest.main()
