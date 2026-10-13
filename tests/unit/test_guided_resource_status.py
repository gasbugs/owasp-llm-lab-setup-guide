import sys
from pathlib import Path
import unittest
from unittest.mock import Mock
from botocore.exceptions import ClientError
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'llm-security-control-plane/guided-bedrock-gateway'))
from resource_status import inventory

class ResourceStatus(unittest.TestCase):
    def test_absence_and_denial_are_distinct_and_read_only(self):
        for denied, expected in [(False, 'absent'), (True, 'unknown')]:
            sdk = {key: Mock() for key in ('sts','s3','vectors','iam','agent','bedrock')}
            sdk['sts'].get_caller_identity.return_value = {'Account': '123456789012'}
            for key, method in [('s3','head_bucket'),('vectors','get_vector_bucket'),('vectors','get_index'),('iam','get_role')]:
                getattr(sdk[key], method).side_effect = ClientError({'Error':{'Code':'AccessDenied' if denied else 'ResourceNotFoundException'}}, 'Get')
            sdk['agent'].list_knowledge_bases.return_value = {'knowledgeBaseSummaries': []}
            template = {key:key for key in ('source_bucket','vector_bucket','index_arn','role_name','knowledge_base_name','data_source_name')}
            result = inventory('P02', provider_mode='aws', p02_template=lambda _:template, client_factory=lambda _:sdk)
            self.assertEqual(result['state'], expected)
            self.assertTrue(result['read_only'])
            self.assertEqual(len(result['resources']),6)
            for client in sdk.values():
                self.assertFalse(any(str(call).startswith(('call.create','call.delete','call.put','call.start')) for call in client.mock_calls))
                client.close.assert_called_once()
    def test_fixture_does_not_connect_to_aws(self):
        factory=Mock()
        result=inventory('P02',provider_mode='contract',p02_template=Mock(),client_factory=factory)
        self.assertEqual(result['state'],'unavailable');factory.assert_not_called()

    def test_inventory_contains_document_and_connection_details(self):
        sdk={key:Mock() for key in ('sts','s3','vectors','iam','agent','bedrock')}
        sdk['sts'].get_caller_identity.return_value={'Account':'123456789012'}
        sdk['s3'].head_bucket.return_value={}
        sdk['s3'].list_objects_v2.return_value={'Contents':[{'Size':42,'LastModified':'2026-10-10'}]}
        sdk['vectors'].get_vector_bucket.return_value={}
        sdk['vectors'].get_index.return_value={'index':{'dimension':1024,'distanceMetric':'cosine','dataType':'float32'}}
        sdk['iam'].get_role.return_value={}
        sdk['agent'].list_knowledge_bases.return_value={'knowledgeBaseSummaries':[{'name':'kb','knowledgeBaseId':'kb-id'}]}
        sdk['agent'].get_knowledge_base.return_value={'knowledgeBase':{'name':'kb','status':'ACTIVE','storageConfiguration':{'type':'S3_VECTORS','s3VectorsConfiguration':{'indexArn':'owned-index'}},'knowledgeBaseConfiguration':{'vectorKnowledgeBaseConfiguration':{'embeddingModelArn':'titan'}},'roleArn':'owned-role'}}
        sdk['agent'].list_data_sources.return_value={'dataSourceSummaries':[{'name':'ds','dataSourceId':'ds-id','status':'AVAILABLE'}]}
        sdk['agent'].get_data_source.return_value={'dataSource':{'name':'ds','dataSourceConfiguration':{'s3Configuration':{'bucketArn':'owned-source','inclusionPrefixes':['h02/knowledge/']}}}}
        sdk['agent'].list_ingestion_jobs.return_value={'ingestionJobSummaries':[{'status':'COMPLETE','startedAt':'2026-10-10','statistics':{'numberOfNewDocumentsIndexed':1}}]}
        t=dict(source_bucket='source',vector_bucket='vectors',index_arn='owned-index',role_name='role',knowledge_base_name='kb',data_source_name='ds')
        result=inventory('P02',provider_mode='aws',p02_template=lambda _:t,client_factory=lambda _:sdk)
        self.assertEqual(result['state'],'present')
        self.assertTrue(all(row.get('console_url','').startswith('https://us-east-1.console.aws.amazon.com/') for row in result['resources']))
        by_type={row['type']:row for row in result['resources']}
        self.assertEqual(by_type['S3 source bucket']['facts']['문서 수'],'1개')
        self.assertEqual(by_type['Knowledge Base']['facts']['연결 인덱스'],'owned-index')
        self.assertEqual(by_type['Data source']['facts']['최근 동기화'],'COMPLETE')
        self.assertFalse(any(str(call).startswith(('call.create','call.delete','call.put','call.start')) for client in sdk.values() for call in client.mock_calls))
