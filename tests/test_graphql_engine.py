import pytest
from unittest.mock import patch, MagicMock
from modules.pipeline.validators.graphql_engine.schema_inference import infer_schema, brute_force_fields
from modules.pipeline.validators.graphql_deep_validator import GraphQLDeepValidator

@patch('requests.post')
def test_schema_inference_suggestion(mock_post):
    mock_resp = MagicMock()
    mock_resp.text = 'Cannot query field "usre" on type "Query". Did you mean "user"?'
    mock_resp.status_code = 400
    mock_post.return_value = mock_resp

    schema = infer_schema("http://target/graphql")
    assert any("user" in v for v in schema.values()), "Failed to parse suggestion error"

@patch('requests.post')
def test_graphql_batch_query_abuse(mock_post):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"data": {"q0": {"__typename": "Query"}, "q1": {"__typename": "Query"}}}'
    mock_post.return_value = mock_resp

    validator = GraphQLDeepValidator()
    result = validator.run({"endpoints": ["http://target/graphql"]})
    
    assert result is not None
    assert result.vulnerability == "graphql-batch-query-bypass"

@patch('requests.post')
def test_graphql_idor_validation(mock_post):
    def side_effect(*args, **kwargs):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        query = kwargs.get('json', {}).get('query', '')
        if "q0:__typename" in query:
            mock_resp.status_code = 400 # fail batch
        elif "a { " * 16 in query:
            mock_resp.status_code = 400 # fail depth
            mock_resp.elapsed.total_seconds = lambda: 0.1
        elif "user(id: 1)" in query:
            mock_resp.json.return_value = {"data": {"user": {"id": "1", "email": "admin@a.com"}}}
        elif "user(id: 2)" in query:
            mock_resp.json.return_value = {"data": {"user": {"id": "2", "email": "user@a.com"}}}
        return mock_resp

    mock_post.side_effect = side_effect

    validator = GraphQLDeepValidator()
    result = validator.run({"endpoints": ["http://target/graphql"], "cookie": "session=123"})
    
    assert result is not None
    assert result.vulnerability == "graphql-idor"