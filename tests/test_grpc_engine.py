import pytest
from unittest.mock import patch, MagicMock
from modules.pipeline.validators.grpc_validator import gRPCValidator

@patch('subprocess.run')
def test_grpc_reflection_and_unauth(mock_run):
    def side_effect(args, **kwargs):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        if "list" in args and len(args) == 4:
            mock_proc.stdout = "helloworld.Greeter\ngrpc.reflection.v1alpha.ServerReflection"
            mock_proc.stderr = ""
        else:
            mock_proc.stdout = "{}"
            mock_proc.stderr = ""
        return mock_proc

    mock_run.side_effect = side_effect

    validator = gRPCValidator()
    validator._grpcurl_available = True
    
    result = validator.run({"endpoints": ["grpc://target:50051"]})
    
    assert result is not None
    assert result.vulnerability == "grpc-reflection-enabled"

@patch('subprocess.run')
def test_grpc_unauthenticated_fallback(mock_run):
    def side_effect(args, **kwargs):
        mock_proc = MagicMock()
        if "list" in args and len(args) == 4:
            mock_proc.returncode = 1
            mock_proc.stdout = ""
            mock_proc.stderr = "Failed"
        elif "helloworld.Greeter" in args:
            mock_proc.returncode = 0
            mock_proc.stdout = "{}"
            mock_proc.stderr = ""
        return mock_proc

    mock_run.side_effect = side_effect

    validator = gRPCValidator()
    validator._grpcurl_available = True
    
    result = validator.run({"endpoints": ["grpc://target:50051"]})
    
    assert result is not None
    assert result.vulnerability == "grpc-unauthenticated-access"