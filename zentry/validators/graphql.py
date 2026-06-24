"""
zentry/validators/graphql.py

GraphQL Validator
"""
import json
from typing import Dict, Any, Optional

import requests

from .base import BaseValidator, Finding

class GraphQLValidator(BaseValidator):
    """
    Validator for GraphQL vulnerabilities.
    """

    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          ...FullType
        }
        directives {
          name
          description
          locations
          args {
            ...InputValue
          }
        }
      }
    }

    fragment FullType on __Type {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          ...InputValue
        }
        type {
          ...TypeRef
        }
        isDeprecated
        deprecationReason
      }
      inputFields {
        ...InputValue
      }
      interfaces {
        ...TypeRef
      }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes {
        ...TypeRef
      }
    }

    fragment InputValue on __InputValue {
      name
      description
      type { ...TypeRef }
      defaultValue
    }

    fragment TypeRef on __Type {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                  }
                }
              }
            }
          }
        }
      }
    }
    """

    def validate(self, url: str, params: Optional[Dict[str, Any]] = None) -> Optional[Finding]:
        """
        Checks if GraphQL introspection is enabled.
        """
        if "/graphql" not in url.lower():
            return None

        try:
            session = self.get_auth_session()
            payload = {"query": self.INTROSPECTION_QUERY}
            req = session.post(url, json=payload, timeout=20)

            if req.status_code == 200 and "data" in req.json() and "__schema" in req.json()["data"]:
                description = "GraphQL introspection is enabled, exposing the entire schema."
                evidence = {
                    "request": {"method": "POST", "url": url, "body": json.dumps(payload)},
                    "response": {"status": req.status_code, "body_snippet": json.dumps(req.json())[:500]},
                }
                return self.confirm_finding(
                    url=url,
                    type="GRAPHQL_INTROSPECTION",
                    severity="MEDIUM",
                    description=description,
                    evidence=evidence,
                )
        except requests.RequestException:
            pass
        
        return None
