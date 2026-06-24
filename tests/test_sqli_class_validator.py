import pytest
import requests
from zentry.validators import SQLiValidator
from zentry.session import ValidationResult

def test_sqli_validator_confirm_finding():
    validator = SQLiValidator()

    # Create fake requests.PreparedRequest and requests.Response objects
    req = requests.PreparedRequest()
    req.prepare(
        method="POST",
        url="http://altoro.testfire.net/doLogin",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={"uid": "admin'", "passw": "admin"},
    )

    res = requests.Response()
    res.status_code = 500
    res.reason = "Internal Server Error"
    res.headers["Content-Type"] = "text/html"
    res._content = b"You have an error in your SQL syntax; check the manual..."
    res.request = req

    result = validator.confirm_finding(
        request_obj=req,
        response_obj=res,
        vulnerability="sql-injection",
        severity="high",
        confidence=0.95,
        param="uid",
        payload="admin'",
        impact="Test SQL injection impact",
        remediation="Test SQL injection remediation",
    )

    assert isinstance(result, ValidationResult)
    assert result.success is True
    assert result.vulnerability == "sql-injection"
    assert result.confidence == 0.95
    assert result.severity == "high"

    # Check evidence bundle
    assert result.evidence_bundle is not None
    assert "POST /doLogin HTTP/1.1" in result.evidence_bundle.raw_request
    assert "Content-Type: application/x-www-form-urlencoded" in result.evidence_bundle.raw_request
    assert "uid=admin%27&passw=admin" in result.evidence_bundle.raw_request

    assert "HTTP/1.1 500 Internal Server Error" in result.evidence_bundle.raw_response
    assert "Content-Type: text/html" in result.evidence_bundle.raw_response
    assert "You have an error in your SQL syntax" in result.evidence_bundle.raw_response
