try:
    import httpx
    HAS_HTTPX = True
except Exception:
    HAS_HTTPX = False

from typing import Dict

class JiraIntegration:
    def __init__(self, base_url: str = None, auth: Dict = None):
        self.base_url = base_url
        self.auth = auth

    def create_issue(self, project: str, summary: str, description: str) -> Dict:
        issue = {'project': project, 'summary': summary, 'description': description}
        if HAS_HTTPX and self.base_url:
            try:
                url = f"{self.base_url}/rest/api/2/issue"
                r = httpx.post(url, json={'fields': issue}, auth=self.auth, timeout=5.0)
                return {'status': r.status_code, 'ok': r.status_code < 300, 'resp': r.text}
            except Exception as e:
                return {'status': 'error', 'error': str(e)}
        print('JIRA-ISSUE:', issue)
        return {'status': 'printed', 'ok': True}
