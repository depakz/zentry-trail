import pytest
import requests
import re
from unittest.mock import MagicMock, patch
from urllib.parse import urljoin, urlparse

from core.auth_manager import AuthManager
from modules.pipeline.validators.biz_logic_validator import BizLogicValidator
from modules.pipeline.validators.default_credential_validator import DefaultCredentialValidator
from modules.pipeline.validators.sqli_validator import SQLiValidator
from modules.pipeline.validators.xss_validator import XSSValidator
from modules.pipeline.validators.sensitive_file_validator import SensitiveFileValidator
from modules.pipeline.engine.models import ValidationResult

class MockResponse:
    def __init__(self, text, status_code=200, cookies=None, request=None, url="http://example.com"):
        self.text = text
        self.status_code = status_code
        self.cookies = cookies or {}
        self.headers = {"Content-Type": "text/html"}
        self.request = request or MagicMock()
        self.url = url
        self.reason = "OK"

    @property
    def content(self):
        return self.text.encode('utf-8')

def test_auth_manager_login_success():
    manager = AuthManager(target="http://example.com", credentials={"username": "admin", "password": "password"})
    
    mock_get = MockResponse('<form action="/doLogin"><input name="uid"/><input type="password" name="passw"/></form>')
    mock_post = MockResponse('<html>Welcome, admin!</html>', cookies={"session_id": "12345"})
    mock_post.request = MagicMock()
    mock_post.request.url = "http://example.com/doLogin"
    mock_post.request.method = "POST"
    mock_post.request.headers = {}
    mock_post.request.body = "uid=admin&passw=password"
    
    with patch.object(requests.Session, 'get', return_value=mock_get) as mock_g, \
         patch.object(requests.Session, 'post', return_value=mock_post) as mock_p:
        
        # Inject cookie manually to requests.Session cookies since dict_from_cookiejar reads from there
        mock_p.return_value.cookies = {"session_id": "12345"}
        
        # Override dict_from_cookiejar globally for this test
        orig_dict_from_cookiejar = requests.utils.dict_from_cookiejar
        requests.utils.dict_from_cookiejar = lambda jar: {"session_id": "12345"}
        try:
            success = manager.login("http://example.com/login", "uid", "passw")
            assert success is True
            assert manager.authenticated is True
            assert manager.auth_cookies == {"session_id": "12345"}
            assert manager.base_url == "http://example.com"
        finally:
            requests.utils.dict_from_cookiejar = orig_dict_from_cookiejar

def test_auth_manager_login_failure():
    manager = AuthManager(target="http://example.com", credentials={"username": "admin", "password": "wrong"})
    
    mock_get = MockResponse('<form action="/doLogin"><input name="uid"/><input type="password" name="passw"/></form>')
    mock_post = MockResponse('<input type="password" name="passw"/>Invalid Credentials', cookies={})
    
    with patch.object(requests.Session, 'get', return_value=mock_get), \
         patch.object(requests.Session, 'post', return_value=mock_post):
        
        success = manager.login("http://example.com/login", "uid", "passw")
        assert success is False
        assert manager.authenticated is False

def test_auth_manager_dual_session():
    manager = AuthManager(target="http://example.com", credentials={"username": "admin", "password": "password"})
    manager.credentials2 = {"username": "user2", "password": "password"}
    
    mock_get = MockResponse('<form action="/doLogin"><input name="uid"/><input type="password" name="passw"/></form>')
    mock_post_user1 = MockResponse('<html>Welcome, admin!</html>', cookies={"session_id": "user1-sess"})
    mock_post_user2 = MockResponse('<html>Welcome, user2!</html>', cookies={"session_id": "user2-sess"})
    
    with patch.object(requests.Session, 'get', return_value=mock_get), \
         patch.object(requests.Session, 'post', side_effect=[mock_post_user1, mock_post_user2]):
        
        orig_dict_from_cookiejar = requests.utils.dict_from_cookiejar
        try:
            # We mock the return of dict_from_cookiejar contextually using global counter or similar state checks
            call_count = [0]
            def mock_dict(jar):
                if call_count[0] == 0:
                    call_count[0] += 1
                    return {"session_id": "user1-sess"}
                return {"session_id": "user2-sess"}
            
            requests.utils.dict_from_cookiejar = mock_dict
            success1 = manager.login("http://example.com/login", "uid", "passw")
            success2 = manager.login_user2("http://example.com/login", "uid", "passw")
            
            assert success1 is True
            assert success2 is True
            assert manager.authenticated is True
            assert manager.authenticated2 is True
            assert manager.auth_cookies == {"session_id": "user1-sess"}
            assert manager.auth_cookies2 == {"session_id": "user2-sess"}
        finally:
            requests.utils.dict_from_cookiejar = orig_dict_from_cookiejar

@pytest.mark.asyncio
async def test_biz_logic_validator_idor_dual_session():
    # Setup AuthManager with two logged in sessions
    manager = AuthManager(target="http://altoro.testfire.net", credentials={"username": "admin", "password": "password"})
    manager.authenticated = True
    manager.auth_cookies = {"session_id": "user1-sess"}
    
    manager.credentials2 = {"username": "user2", "password": "password"}
    manager.authenticated2 = True
    manager.auth_cookies2 = {"session_id": "user2-sess"}
    manager.session2 = requests.Session()
    manager.session2.cookies.update(manager.auth_cookies2)
    
    # Mocking Account main page response containing accounts, and the showAccount IDOR responses
    mock_main = MockResponse('Account details: Account Number 800001, 800002')
    # User A requesting user B's account should work (HTTP 200)
    mock_req = MagicMock(spec=requests.PreparedRequest)
    mock_req.url = "http://altoro.testfire.net/bank/showAccount?listAccounts=800003"
    mock_req.method = "GET"
    mock_req.headers = {}
    mock_req.body = None
    
    # Make sure BizLogicValidator's check "len(r_test.text) > 100" is satisfied
    mock_idor_resp = MockResponse('Account Summary for 800003: balance is $500. This is long enough to satisfy IDOR checks. Lorem Ipsum dolors sit amet...', status_code=200, request=mock_req)
    
    state = {
        "url": "http://altoro.testfire.net/bank/showAccount?listAccounts=800001",
        "endpoints": ["/bank/showAccount?listAccounts=800001"],
        "auth_manager": manager,
        "auth_cookies": manager.auth_cookies
    }
    
    validator = BizLogicValidator()
    
    with patch.object(requests.Session, 'get', side_effect=[mock_main, mock_idor_resp, mock_idor_resp]):
        result = await validator.run(state)
        
        assert result is not None
        assert result.success is True
        assert result.vulnerability == "idor-cross-account"
        assert result.severity == "critical"

def test_default_credential_validator_masks_passwords():
    # Test DefaultCredentialValidator and verify that passwords are masked in output
    validator = DefaultCredentialValidator()
    
    mock_get_login = MockResponse('<form action="/doLogin"><input name="uid"/><input type="password" name="passw"/></form>')
    # Mock a successful login on the 3rd attempt (jsmith/demo1234)
    mock_req = MagicMock()
    mock_req.url = "http://altoro.testfire.net/doLogin"
    mock_req.method = "POST"
    mock_req.headers = {}
    mock_req.body = "uid=admin&passw=password"
    mock_success = MockResponse('Welcome back! altoroaccounts summary', status_code=200, cookies={"session_id": "logged-in-session"}, request=mock_req)
    mock_fail = MockResponse('Invalid Credentials', status_code=200)
    
    state = {
        "url": "http://altoro.testfire.net/login.jsp",
        "auth_manager": AuthManager(target="http://altoro.testfire.net")
    }
    
    with patch.object(requests, 'get', return_value=mock_get_login), \
         patch.object(requests, 'post', side_effect=[mock_fail, mock_fail, mock_success] + [mock_fail]*50):
        
        result = validator.run(state)
        
        if isinstance(result, list):
            result = [r for r in result if r.vulnerability == "default-credentials"][0]
            
        assert result is not None
        assert result.success is True
        assert result.vulnerability == "default-credentials"
        assert result.severity == "critical"
        # Confirm payload (reconstructed inside Evidence as matched) is MASKED
        assert result.evidence.matched.startswith("username:")
        assert "password" not in result.evidence.matched
        assert "***" not in result.evidence.matched

@pytest.mark.asyncio
async def test_sqli_validator_enrichment():
    # Test that SQLiValidator re-tests queryxpath.jsp when auth_manager is present
    validator = SQLiValidator()
    manager = AuthManager(target="http://altoro.testfire.net", credentials={"username": "admin", "password": "password"})
    manager.authenticated = True
    
    state = {
        "url": "http://altoro.testfire.net",
        "auth_manager": manager,
        "auth_cookies": {}
    }
    
    # Mocking xpath query response
    mock_req = MagicMock()
    mock_req.url = "http://altoro.testfire.net/bank/queryxpath.jsp?search=payload"
    mock_req.method = "GET"
    mock_req.headers = {}
    mock_req.body = None
    mock_xpath_resp = MockResponse('Account: admin, Balance: $1000', status_code=200, request=mock_req)
    
    with patch.object(requests.Session, 'get', return_value=mock_xpath_resp):
        result = validator.run(state)
        assert result is not None
        assert result.success is True
        assert result.vulnerability == "sql-injection"
        assert "queryxpath.jsp" in result.evidence.request["target"]

@pytest.mark.asyncio
async def test_xss_validator_enrichment():
    # Test that XSSValidator re-tests feedback.jsp and search.jsp when auth_manager is present
    validator = XSSValidator()
    manager = AuthManager(target="http://altoro.testfire.net", credentials={"username": "admin", "password": "password"})
    manager.authenticated = True
    
    state = {
        "url": "http://altoro.testfire.net",
        "auth_manager": manager,
        "auth_cookies": {}
    }
    
    mock_feedback_get = MockResponse('Feedback page', status_code=200)
    mock_feedback_post = MockResponse('Feedback submitted', status_code=200)
    # Return feedback list containing our payload
    mock_req = MagicMock()
    mock_req.url = "http://altoro.testfire.net/feedback.jsp"
    mock_req.method = "POST"
    mock_req.headers = {}
    mock_req.body = "comments=<u>"
    mock_feedback_check = MockResponse('Feedback List: <u>zentry_stored_xss_test</u>', status_code=200, request=mock_req)
    
    with patch.object(requests.Session, 'get', side_effect=[mock_feedback_get, mock_feedback_check]), \
         patch.object(requests.Session, 'post', return_value=mock_feedback_post):
        
        result = validator.run(state)
        assert result is not None
        assert result.success is True
        assert result.vulnerability == "stored-xss"

def test_sensitive_file_validator_enrichment():
    # Test that SensitiveFileValidator re-tests /admin/admin.jsp and flags access control issues
    validator = SensitiveFileValidator()
    manager = AuthManager(target="http://altoro.testfire.net", credentials={"username": "admin", "password": "password"})
    manager.authenticated = True
    
    state = {
        "url": "http://altoro.testfire.net",
        "auth_manager": manager,
        "auth_cookies": {}
    }
    
    mock_req = MagicMock()
    mock_req.url = "http://altoro.testfire.net/admin/admin.jsp"
    mock_req.method = "GET"
    mock_req.headers = {}
    mock_req.body = None
    mock_admin_resp = MockResponse('Welcome to the admin console! manage users here', status_code=200, request=mock_req)
    
    with patch.object(requests.Session, 'get', return_value=mock_admin_resp):
        result = validator.run(state)
        
        if isinstance(result, list):
            result = [r for r in result if "/admin/admin.jsp" in r.evidence.request["url"]][0]
            
        assert result is not None
        assert result.success is True
        assert result.vulnerability == "sensitive-file-exposure"
        assert "/admin/admin.jsp" in result.evidence.request["url"]
