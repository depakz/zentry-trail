import os
import yaml


def test_payload_count_and_structure():
    base = os.path.abspath(os.path.join('avvp', 'payload-library', 'templates'))
    assert os.path.exists(base)
    # expect categories
    cats = ['sql-injection', 'xss', 'auth', 'headers', 'open-redirect']
    for c in cats:
        p = os.path.join(base, c)
        assert os.path.isdir(p)
        files = [f for f in os.listdir(p) if f.endswith('.yaml')]
        assert len(files) >= 5
        # parse one file
        fpath = os.path.join(p, files[0])
        with open(fpath, 'r') as fh:
            obj = yaml.safe_load(fh)
        assert 'id' in obj and 'info' in obj and 'requests' in obj

    # total count
    total = 0
    for root,_,files in os.walk(base):
        for f in files:
            if f.endswith('.yaml'):
                total += 1
    assert total >= 50
