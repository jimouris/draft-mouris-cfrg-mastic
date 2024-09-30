from typing import TypeAlias, Self

class Index:
    def __init__(self, *bits: int):
        for bit in bits:
            assert bit in range(2)
        self.bits = tuple(bits)

    def is_prefix(self, other: Self) -> bool:
        return self.bits == other.bits[:len(self.bits)]

    def left_child(self) -> Self:
        return self.__class__(*self.bits, 0)

    def right_child(self) -> Self:
        return self.__class__(*self.bits, 1)

    def __hash__(self):
        return hash(self.bits)

    def __eq__(self, other):
        return self.bits == other.bits

    def __lt__(self, other):
        assert len(self.bits) == len(other.bits)
        return self.bits < other.bits

    def __repr__(self):
        return repr(self.bits)

class Weight:
    def __init__(self, x: int):
        self.x = x

    def __iadd__(self, other):
        self.x += other.x

    def __repr__(self):
        return repr(self.x)

    def __eq__(self, other):
        return self.x == other.x

    def __ge__(self, other):
        return self.x >= other.x


def mastic_func(measurements: list[tuple[Index, Weight]],
                prefixes: list[Index]) -> dict[Index, Weight]:
    '''
    Compute the total weight for each prefix for the set of
    measurements.
    '''
    r: dict[Index, Weight] = {}
    for (alpha, beta) in measurements:
        for p in prefixes:
            if p.is_prefix(alpha):
                w = r.setdefault(p, Weight(0))
                w += beta
    return r

def weighted_heavy_hitters(measurements: list[tuple[Index, Weight]],
                           threshold: Weight,
                           bit_len: int) -> list[Index]:
    '''
    Compute the weighted heavy hitters for the given threshold.
    '''
    prefixes = [Index(0), Index(1)]
    for level in range(bit_len):
        next_prefixes = []
        for (p, w) in mastic_func(measurements, prefixes).items():
            if w >= threshold:
                if level < bit_len - 1:
                    next_prefixes.append(p.left_child())
                    next_prefixes.append(p.right_child())
                else:
                    next_prefixes.append(p)
        prefixes = next_prefixes
    return sorted(prefixes)
