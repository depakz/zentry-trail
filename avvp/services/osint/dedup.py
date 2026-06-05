from simhash import Simhash

class SimHashDeduplicator:
    def __init__(self, threshold: int = 3):
        self.threshold = threshold
        self.fingerprints = set()

    def _fingerprint(self, text: str) -> int:
        return Simhash(text).value

    def is_duplicate(self, text: str) -> bool:
        fp = self._fingerprint(text)
        for existing in self.fingerprints:
            # Hamming distance
            x = fp ^ existing
            dist = x.bit_count()
            if dist <= self.threshold:
                return True
        self.fingerprints.add(fp)
        return False
