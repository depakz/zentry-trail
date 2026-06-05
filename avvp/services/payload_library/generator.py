import os
from typing import Dict, List

import yaml

from .catalog import PAYLOAD_CATALOG, iter_catalog, template_record


def generate(n: int = 60, out_dir: str = None) -> str:
    out_dir = out_dir or os.path.join(os.path.dirname(__file__), '..', '..', 'payload-library', 'templates')
    os.makedirs(out_dir, exist_ok=True)
    # ensure category dirs
    cat_dirs = {}
    for cat in PAYLOAD_CATALOG.keys():
        d = os.path.join(out_dir, cat)
        os.makedirs(d, exist_ok=True)
        cat_dirs[cat] = d

    created = 0
    # populate by cycling categories and their examples
    idx = 0
    while created < n:
        for cat, ex in iter_catalog():
            if created >= n:
                break
            tpl = template_record(cat, ex, idx)
            fname = os.path.join(cat_dirs[cat], tpl['id'] + '.yaml')
            with open(fname, 'w', encoding='utf-8') as f:
                yaml.safe_dump(tpl, f, sort_keys=False)
            created += 1
            idx += 1
    return out_dir


if __name__ == '__main__':
    print('Generating categorized templates...')
    print(generate())
