import os
import yaml
from typing import Dict

class PredicateWriter:
    def __init__(self, out_dir: str = None):
        self.out_dir = out_dir or os.path.join(os.path.dirname(__file__), '..', '..', 'payload-library', 'generated')
        os.makedirs(self.out_dir, exist_ok=True)

    def write_nuclei_template(self, finding: Dict, filename: str = None) -> str:
        tpl = {
            'id': finding.get('finding_id', 'auto-'+str(hash(finding.get('vuln_class','')))),
            'info': {
                'name': finding.get('vuln_class', 'finding'),
                'severity': finding.get('severity', 'medium'),
            },
            'http': [
                {
                    'method': 'GET',
                    'path': [finding.get('uri', '{{BaseURL}}')],
                    'matchers': [
                        {'type': 'word', 'words': [finding.get('evidence_word','')], 'part': 'body'}
                    ]
                }
            ]
        }
        content = yaml.safe_dump(tpl)
        fname = filename or (tpl['id'] + '.yaml')
        out_path = os.path.join(self.out_dir, fname)
        with open(out_path, 'w') as f:
            f.write(content)
        return out_path
