import yaml
from typing import Dict, Any

class PoCGenerator:
    def __init__(self, library_path: str = None):
        self.library_path = library_path

    def render_template(self, template_yaml: str, context: Dict[str, Any]) -> Dict[str, Any]:
        # Load YAML template and substitute simple placeholders {{var}}
        tpl = yaml.safe_load(template_yaml)
        rendered = {}
        for k, v in tpl.items():
            if isinstance(v, str):
                for key, val in context.items():
                    v = v.replace(f"{{{{{key}}}}}", str(val))
            rendered[k] = v
        return rendered
