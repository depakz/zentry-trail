"""Structured payload representation and rendering logic."""

import random
from dataclasses import dataclass


@dataclass
class PayloadGene:
    """Structured payload representation with encoding and wrapper layers."""
    vuln_class: str
    core_payload: str
    encoding_layer: str = "none"
    delimiter: str = ""
    wrapper: str = "none"
    null_byte: bool = False
    case_variant: str = "none"

    def render(self) -> str:
        """Render final injection string with all transformations applied sequentially."""
        payload = self.core_payload

        # 1. Casing
        if self.case_variant == "upper":
            payload = payload.upper()
        elif self.case_variant == "lower":
            payload = payload.lower()
        elif self.case_variant == "mixed":
            payload = "".join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)

        # 2. Wrapper
        if self.wrapper == "json":
            import json
            payload = json.dumps(payload)
        elif self.wrapper == "xml":
            payload = f"<![CDATA[{payload}]]>"
        elif self.wrapper == "base64":
            import base64
            payload = base64.b64encode(payload.encode()).decode()

        # 3. Encoding
        if self.encoding_layer == "url":
            import urllib.parse
            payload = urllib.parse.quote(payload)
        elif self.encoding_layer == "double_url":
            import urllib.parse
            payload = urllib.parse.quote(urllib.parse.quote(payload))
        elif self.encoding_layer == "unicode":
            payload = "".join(f"\\u{ord(c):04x}" for c in payload)
        elif self.encoding_layer == "html_entity":
            payload = "".join(f"&#{ord(c)};" for c in payload)
        elif self.encoding_layer == "hex":
            payload = "".join(f"\\x{ord(c):02x}" for c in payload)

        # 4. Delimiter Mutation
        if self.delimiter:
            payload = self.delimiter + payload + self.delimiter

        # 5. Null Byte Injection
        if self.null_byte:
            payload = payload + "\x00"

        return payload