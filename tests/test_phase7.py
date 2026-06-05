import asyncio
from avvp.services.causal_learner.causal import CausalLearner
from avvp.services.embedding_reasoner.reasoner import EmbeddingReasoner
from avvp.services.chain_ranker.ranker import ChainRanker
from avvp.services.state_propagator.state import ExploitStateMachine


def test_causal_simple():
    pairs = [('A','B'), ('A','B'), ('B','C')]
    cl = CausalLearner()
    cl.fit(pairs)
    assert cl.p('A','B') > 0


def test_embedding_reasoner():
    er = EmbeddingReasoner()
    sims = er.most_similar('login error', ['database error', 'auth failed', 'ok'])
    assert isinstance(sims, list)


def test_chain_ranker():
    cr = ChainRanker()
    chains = [[[{'exploitability':0.9,'impact':0.9,'novelty':0.1}], [{'exploitability':0.2,'impact':0.2,'novelty':0.0}]]]
    ranked = cr.rank(chains)
    assert isinstance(ranked, list)

def test_state_propagator():
    sm = ExploitStateMachine()
    asyncio.run(sm.transition('t1','planned', {'note':'test'}))
    # transition to in_progress
    asyncio.run(sm.transition('t1','in_progress', None))

if __name__ == '__main__':
    asyncio.run(ExploitStateMachine().transition('t1','planned', {'note':'test'}))
