import inspect
import requests
import requests.sessions
from urllib.parse import urlparse
from modules.pipeline.engine.models import Evidence, EvidenceBundle, ValidationResult


class BaseValidator:
    """Base class for all validators providing evidence capture capabilities."""

    # Class-level reference to the shared EvidenceCollector (set by orchestrator)
    _evidence_collector = None
    _evidence_index_counter = 0

    @classmethod
    def set_evidence_collector(cls, collector):
        """Set the shared EvidenceCollector instance for all validators."""
        cls._evidence_collector = collector

    @classmethod
    def _next_evidence_index(cls) -> int:
        """Return and increment the global evidence finding index."""
        cls._evidence_index_counter += 1
        return cls._evidence_index_counter

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)

        # 1. Wrap __init__ to capture auth_manager / session
        orig_init = cls.__init__
        def wrapped_init(self, *args, **init_kwargs):
            sig = inspect.signature(orig_init)
            accepts_auth = 'auth_manager' in sig.parameters
            accepts_session = 'session' in sig.parameters

            auth_mgr = init_kwargs.get('auth_manager')
            sess = init_kwargs.get('session')

            passed_kwargs = dict(init_kwargs)
            if not accepts_auth and 'auth_manager' in passed_kwargs:
                passed_kwargs.pop('auth_manager')
            if not accepts_session and 'session' in passed_kwargs:
                passed_kwargs.pop('session')

            orig_init(self, *args, **passed_kwargs)

            if auth_mgr is not None:
                self.auth_manager = auth_mgr
            if sess is not None:
                self.session = sess
        cls.__init__ = wrapped_init

        # 2. Wrap run to dynamically propagate auth session to requests calls
        if hasattr(cls, 'run'):
            orig_run = cls.run
            if inspect.iscoroutinefunction(orig_run):
                async def wrapped_run(self, state, *args, **kwargs):
                    auth_mgr = None
                    if isinstance(state, dict):
                        auth_mgr = state.get("auth_manager")
                    if not auth_mgr:
                        auth_mgr = getattr(self, "auth_manager", None)
                    else:
                        self.auth_manager = auth_mgr

                    if auth_mgr and getattr(auth_mgr, 'authenticated', False):
                        original_session = requests.sessions.Session

                        class SessionWrapper(requests.Session):
                            def __init__(self, auth_session):
                                self._auth_session = auth_session
                            def request(self, *args, **kwargs):
                                kwargs.setdefault('verify', False)
                                return self._auth_session.request(*args, **kwargs)
                            def __getattribute__(self, name):
                                if name in ('_auth_session', '__enter__', '__exit__', 'request', '__class__'):
                                    return object.__getattribute__(self, name)
                                return getattr(self._auth_session, name)
                            def __setattr__(self, name, value):
                                if name == '_auth_session':
                                    object.__setattr__(self, name, value)
                                else:
                                    setattr(self._auth_session, name, value)
                            def __enter__(self):
                                return self
                            def __exit__(self, exc_type, exc_val, exc_tb):
                                pass

                        def make_session(*args, **kwargs):
                            return SessionWrapper(auth_mgr.get_session())

                        requests.Session = make_session
                        requests.sessions.Session = make_session
                        try:
                            return await orig_run(self, state, *args, **kwargs)
                        finally:
                            requests.Session = original_session
                            requests.sessions.Session = original_session
                    else:
                        return await orig_run(self, state, *args, **kwargs)
                cls.run = wrapped_run
            else:
                def wrapped_run(self, state, *args, **kwargs):
                    auth_mgr = None
                    if isinstance(state, dict):
                        auth_mgr = state.get("auth_manager")
                    if not auth_mgr:
                        auth_mgr = getattr(self, "auth_manager", None)
                    else:
                        self.auth_manager = auth_mgr

                    if auth_mgr and getattr(auth_mgr, 'authenticated', False):
                        original_session = requests.sessions.Session

                        class SessionWrapper(requests.Session):
                            def __init__(self, auth_session):
                                self._auth_session = auth_session
                            def request(self, *args, **kwargs):
                                kwargs.setdefault('verify', False)
                                return self._auth_session.request(*args, **kwargs)
                            def __getattribute__(self, name):
                                if name in ('_auth_session', '__enter__', '__exit__', 'request', '__class__'):
                                    return object.__getattribute__(self, name)
                                return getattr(self._auth_session, name)
                            def __setattr__(self, name, value):
                                if name == '_auth_session':
                                    object.__setattr__(self, name, value)
                                else:
                                    setattr(self._auth_session, name, value)
                            def __enter__(self):
                                return self
                            def __exit__(self, exc_type, exc_val, exc_tb):
                                pass

                        def make_session(*args, **kwargs):
                            return SessionWrapper(auth_mgr.get_session())

                        requests.Session = make_session
                        requests.sessions.Session = make_session
                        try:
                            return orig_run(self, state, *args, **kwargs)
                        finally:
                            requests.Session = original_session
                            requests.sessions.Session = original_session
                    else:
                        return orig_run(self, state, *args, **kwargs)
                cls.run = wrapped_run

    def get_session(self) -> requests.Session:
        """
        Return the authenticated session if available,
        falling back to a plain requests.Session.
        """
        auth_mgr = getattr(self, 'auth_manager', None)
        if auth_mgr and getattr(auth_mgr, 'authenticated', False):
            return auth_mgr.get_session()
        sess = getattr(self, 'session', None)
        if isinstance(sess, requests.Session):
            return sess
        return requests.Session()

    def confirm_finding(
        self,
        request_obj: requests.PreparedRequest,
        response_obj: requests.Response,
        vulnerability: str,
        severity: str = "high",
        confidence: float = 0.9,
        param: str = "",
        payload: str = "",
        impact: str = "",
        remediation: str = "",
        *,
        raw_request: requests.PreparedRequest = None,
        raw_response: requests.Response = None,
    ) -> ValidationResult:
        """
        Confirm a finding and optionally capture HTTP evidence to disk.

        Parameters
        ----------
        request_obj : requests.PreparedRequest
            The request object (used for evidence dict).
        response_obj : requests.Response
            The response object (used for evidence dict).
        vulnerability : str
            The vulnerability type slug.
        severity : str
            Severity level.
        confidence : float
            Confidence score 0.0–1.0.
        param, payload, impact, remediation : str
            Additional finding metadata.
        raw_request : requests.PreparedRequest, optional
            If provided, the actual PreparedRequest for disk evidence capture.
            Falls back to request_obj if not given.
        raw_response : requests.Response, optional
            If provided, the actual Response for disk evidence capture.
            Falls back to response_obj if not given.

        Returns
        -------
        ValidationResult with evidence_bundle and file paths.
        """
        # Resolve raw objects — prefer explicit raw_request/raw_response,
        # fall back to the positional request_obj/response_obj.
        actual_request = raw_request if raw_request is not None else request_obj
        actual_response = raw_response if raw_response is not None else response_obj

        # 1. Parse raw request from request_obj
        req_text = ""
        if request_obj is not None:
            try:
                parsed = urlparse(request_obj.url)
                path = parsed.path
                if parsed.query:
                    path = f"{path}?{parsed.query}"
                if not path:
                    path = "/"
                request_line = f"{request_obj.method} {path} HTTP/1.1"
                headers = [f"{k}: {v}" for k, v in request_obj.headers.items()]
                if "Host" not in request_obj.headers and parsed.netloc:
                    headers.insert(0, f"Host: {parsed.netloc}")
                header_text = "\n".join(headers)
                body_text = ""
                if request_obj.body:
                    if isinstance(request_obj.body, bytes):
                        body_text = request_obj.body.decode('utf-8', errors='ignore')
                    else:
                        body_text = str(request_obj.body)
                req_text = f"{request_line}\n{header_text}\n\n{body_text}"
            except Exception:
                pass

        # 2. Parse raw response from response_obj
        res_text = ""
        if response_obj is not None:
            try:
                status_line = f"HTTP/1.1 {response_obj.status_code} {response_obj.reason}"
                headers = [f"{k}: {v}" for k, v in response_obj.headers.items()]
                header_text = "\n".join(headers)
                body_text = response_obj.text[:4096] if response_obj.text else ""
                res_text = f"{status_line}\n{header_text}\n\n{body_text}"
            except Exception:
                pass

        # 3. Create Evidence and EvidenceBundle
        evidence_obj = Evidence(
            request={
                "target": request_obj.url if request_obj else "",
                "param": param,
                "payload": payload,
                "method": request_obj.method if request_obj else "GET",
                "headers": dict(request_obj.headers) if request_obj else None,
            },
            response={
                "status": response_obj.status_code if response_obj else 200,
                "headers": dict(response_obj.headers) if response_obj else None,
                "snippet": response_obj.text[:400] if response_obj else "",
            },
            matched=payload,
        )

        bundle = EvidenceBundle(
            raw_request=req_text,
            raw_response=res_text,
            matched_indicator=payload,
        )

        # 4. Capture evidence to disk if collector is available
        evidence_paths = {"evidence_req_path": "", "evidence_res_path": ""}
        if self.__class__._evidence_collector is not None:
            try:
                target_url = request_obj.url if request_obj else ""
                idx = self.__class__._next_evidence_index()
                evidence_paths = self.__class__._evidence_collector.save_single_evidence(
                    index=idx,
                    vuln=vulnerability,
                    endpoint=target_url,
                    prepared_request=actual_request,
                    response_obj=actual_response,
                )
            except Exception:
                pass

        # Store paths in the bundle metadata for downstream consumption
        bundle.metadata["evidence_req_path"] = evidence_paths.get("evidence_req_path", "")
        bundle.metadata["evidence_res_path"] = evidence_paths.get("evidence_res_path", "")

        result = ValidationResult(
            success=True,
            confidence=confidence,
            severity=severity,
            vulnerability=vulnerability,
            evidence=evidence_obj,
            evidence_bundle=bundle,
            impact=impact,
            remediation=remediation,
        )

        return result
