import json
import os
from typing import List, Dict

class Reporter:
    def __init__(self, out_dir: str = None):
        self.out_dir = out_dir or os.path.join(os.path.dirname(__file__), '..', '..', 'reports')
        os.makedirs(self.out_dir, exist_ok=True)

    def write_sarif(self, findings: List[Dict], filename: str = 'report.sarif.json') -> str:
        sarif = {
            'version': '2.1.0',
            'runs': [
                {
                    'tool': {'driver': {'name': 'avvp-reporter', 'rules': []}},
                    'results': findings
                }
            ]
        }
        out = os.path.join(self.out_dir, filename)
        with open(out, 'w') as f:
            json.dump(sarif, f, indent=2)
        return out

    def write_html(self, findings: List[Dict], filename: str = 'report.html') -> str:
        outpath = os.path.join(self.out_dir, filename)
        lines = ['<html><head><meta charset="utf-8"><title>AVVP Report</title></head><body>']
        lines.append('<h1>AVVP Findings</h1>')
        for f in findings:
            lines.append('<div class="finding">')
            lines.append(f"<h2>{f.get('message','Finding')}</h2>")
            lines.append('<pre>')
            lines.append(json.dumps(f, indent=2))
            lines.append('</pre>')
            lines.append('</div>')
        lines.append('</body></html>')
        with open(outpath, 'w') as fh:
            fh.write('\n'.join(lines))
        return outpath
