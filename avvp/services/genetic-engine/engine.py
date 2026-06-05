import random
from typing import List

class GeneticPayloadEngine:
    def __init__(self, population_size=20, generations=10, mutation_rate=0.2):
        self.population_size = population_size
        self.generations = generations
        self.mutation_rate = mutation_rate

    def seed_population(self, base_payload: str) -> List[str]:
        return [base_payload for _ in range(self.population_size)]

    def mutate(self, payload: str) -> str:
        # simple mutations: case flip, url-encode < to %3C, insert noop
        choices = [lambda s: s.swapcase(), lambda s: s.replace('<', '%3C'), lambda s: s + ' ']
        p = payload
        if random.random() < self.mutation_rate:
            f = random.choice(choices)
            p = f(p)
        return p

    def evaluate(self, payload: str, target: dict) -> float:
        # heuristic fitness: length and presence of markers
        score = 0.0
        if '<script>' in payload.lower():
            score += 0.6
        score += min(1.0, len(payload) / 100.0)
        return score

    def evolve(self, base_payload: str, target: dict) -> str:
        population = self.seed_population(base_payload)
        for gen in range(self.generations):
            scored = [(self.evaluate(p, target), p) for p in population]
            scored.sort(reverse=True)
            # keep top 20%
            survivors = [p for _, p in scored[: max(1, len(scored)//5)]]
            # breed
            new_pop = survivors[:]
            while len(new_pop) < self.population_size:
                if len(survivors) > 1:
                    a, b = random.sample(survivors, 2)
                else:
                    a = b = survivors[0]
                child = self.crossover(a, b)
                child = self.mutate(child)
                new_pop.append(child)
            population = new_pop
        best = max(population, key=lambda p: self.evaluate(p, target))
        return best

    def crossover(self, a: str, b: str) -> str:
        # simple midpoint crossover
        i = len(a)//2
        j = len(b)//2
        return a[:i] + b[j:]
