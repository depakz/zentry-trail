"""Schema Extraction Without Introspection."""
import requests
from typing import Dict, List, Set, Any

HOPPER_WORDLIST = ["id", "name", "email", "password", "token", "admin", "user", "me"]

def infer_schema(api_url: str) -> Dict[str, Set[str]]:
    """Reconstruct schema by analyzing 'Did you mean X?' errors"""
    schema_map: Dict[str, Set[str]] = {}
    
    for base_field in HOPPER_WORDLIST:
        for type_hint in ["Query", "User", "Post"]:  # Common type guesses
            for alt in ["_id", "s", "1"]:  # Intentional typos to trigger suggestion
                query = f"""query {{ {base_field}{alt} {{ id }} }}"""
                try:
                    response = requests.post(api_url, json={"query": query}, timeout=5)
                    if response.status_code and "did you mean" in response.text.lower():
                        # Parse suggested field from error
                        suggested_parts = response.text.lower().split("did you mean ")
                        if len(suggested_parts) > 1:
                            suggested = suggested_parts[1].split(".")[0].replace("?", "").replace('"', '').replace("'", "").strip()
                            if type_hint not in schema_map:
                                schema_map[type_hint] = set()
                            schema_map[type_hint].add(suggested)
                except Exception as e:
                    continue
    return schema_map

def brute_force_fields(api_url: str, schema_map: Dict[str, Set[str]], wordlist: List[str] = None) -> Dict[str, Dict[str, bool]]:
    """Test inferred schema against wordlist."""
    if wordlist is None:
        wordlist = HOPPER_WORDLIST
        
    results: Dict[str, Dict[str, bool]] = {}
    for obj_type, fields in schema_map.items():
        results[obj_type] = {}
        for field in wordlist:
            if field in fields:
                results[obj_type][field] = True  # Confirmed field
            else:
                # Brute-force test
                query = f"""query {{ {obj_type.lower()} {{ {field} }} }}"""
                try:
                    response = requests.post(api_url, json={"query": query}, timeout=5)
                    if response.status_code == 200 and "data" in response.json():
                        results[obj_type][field] = True
                    else:
                        results[obj_type][field] = False
                except Exception as e:
                    results[obj_type][field] = False
    return results
```