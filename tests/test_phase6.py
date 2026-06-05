import asyncio
from avvp.services.attack_selector.service import AttackSelector
from avvp.services.poc_generator.service import PoCGenerator
from avvp.services.genetic_engine.engine import GeneticPayloadEngine
from avvp.services.jwt_engine.jwt_engine import JWTEngine


def test_attack_selector():
    sel = AttackSelector()
    res = sel.rank_strategies({'candidate_attacks':['xss','sqli'],'historical_success':{'xss':0.1,'sqli':0.5}}, [0.2,0.8])
    assert isinstance(res, list) and res[0]['attack'] == 'sqli'


def test_poc_render():
    pg = PoCGenerator()
    tpl = """id: test\npath: /?q={{param}}\n"""
    out = pg.render_template(tpl, {'param':'1'})
    assert 'path' in out and '1' in out['path']


def test_genetic_evolve():
    ge = GeneticPayloadEngine(population_size=6, generations=2)
    best = ge.evolve('<script>alert(1)</script>', {})
    assert isinstance(best, str)


def test_jwt_checks():
    je = JWTEngine()
    # alg none example (header.payload.signature mocked)
    token = 'eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiMSJ9.'
    assert je.check_alg_none(token) is True
