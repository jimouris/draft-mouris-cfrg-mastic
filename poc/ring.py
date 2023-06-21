"""Definitions of ring used in this spec."""

from __future__ import annotations
import hashlib


class RingElem:
    """The base class for ring elements."""

    def __init__(self, val, mod):
        self.val = val % mod
        self.MODULUS = mod

    def __add__(self, other):
        if self.MODULUS != other.MODULUS:
            raise ValueError("Different moduli in add:", self.MODULUS, other.MODULUS)
        if isinstance(other, RingElem):
            return RingElem((self.val + other.val) % self.MODULUS, self.MODULUS)
        raise ValueError("Unsupported operand type for +")

    def __sub__(self, other):
        if self.MODULUS != other.MODULUS:
            raise ValueError("Different moduli in sub:", self.MODULUS, other.MODULUS)
        if isinstance(other, RingElem):
            return RingElem((self.val - other.val) % self.MODULUS, self.MODULUS)
        raise ValueError("Unsupported operand type for -")

    def __mul__(self, other):
        if self.MODULUS != other.MODULUS:
            raise ValueError("Different moduli in mul:", self.MODULUS, other.MODULUS)
        if isinstance(other, RingElem):
            return RingElem((self.val * other.val) % self.MODULUS, self.MODULUS)
        raise ValueError("Unsupported operand type for *")

    def __neg__(self):
        return RingElem((-self.val) % self.MODULUS, self.MODULUS)

    def __eq__(self, other):
        if isinstance(other, RingElem):
            return self.val == other.val
        return False

    def __str__(self):
        return str(self.val)

    def __repr__(self):
        return str(self.val)

    def as_unsigned(self) -> Unsigned:
        return int(self.val)

    def hash(self):
        """Compute the hash val of the ring element."""
        sha256 = hashlib.sha256()
        sha256.update(self.val.to_bytes(8, 'big'))
        return sha256.digest()

    def conditional_select(self, inp: Bytes) -> Bytes:
        """
        Return `inp` unmodified if `self == 1`; otherwise return the all-zero
        string of the same length.

        Implementation note: To protect the code from timing side channels, it
        is important to implement this algorithm in constant time.
        """

        # Convert the element into a bitmask such that `m == 255` if
        # `self == 1` and `m == 0` otherwise.
        m = 0
        v = self.as_unsigned()
        for i in range(8):
            m |= v << i
        return bytes(map(lambda x: m & x, inp))

class Ring:
    """The base class for rings."""

    def __init__(self, mod):
        self.MODULUS = mod
        self.ENCODED_SIZE = 8

    def __str__(self):
        return 'Ring(' + str(self.MODULUS) + ')'

    def new_elm(self, val):
        return RingElem(val, self.MODULUS)

    def zero(self):
        return RingElem(0, self.MODULUS)

    def one(self):
        return RingElem(1, self.MODULUS)

    def zeros(self, length: Unsigned) -> Vec[Field]:
        vec = [self.zero() for _ in range(length)]
        return vec


def main():
    '''Run some tests.'''
    r = Ring(2**6)
    print(r, 'tests')
    el_1 = r.new_elm(42)
    el_2 = r.new_elm(20)
    sum = el_1 + el_2

    assert el_1.as_unsigned() == 42
    assert el_2.as_unsigned() == 20
    assert sum.as_unsigned() == 62

    sum += r.new_elm(10)

    assert sum.as_unsigned() == 8
    assert (r.new_elm(-1) * sum).as_unsigned() == 56

    r2 = Ring(2)
    print(r2, 'tests')
    assert r2.one().as_unsigned() == 1
    assert r2.zero().as_unsigned() == 0
    assert r2.one() + r2.one() == r2.zero()
    assert r2.one() * r2.one() == r2.one()
    assert -r2.one() == r2.one()
    assert r2.one().conditional_select(b'hello') == b'hello'
    assert r2.zero().conditional_select(b'hello') == bytes([0, 0, 0, 0, 0])

    try:
        r2.one() + r.one()
        assert False
    except Exception as e:
        print("Caught error correctly:", str(e))


if __name__ == '__main__':
    main()