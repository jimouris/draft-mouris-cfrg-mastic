"""Definitions of ring used in this spec."""

from __future__ import annotations
import hashlib


class RingElem:
    """The base class for ring elements."""

    def __init__(self, val, mod):
        self.val = val % mod
        self.MODULUS = mod

    def __add__(self, other):
        if isinstance(other, RingElem):
            return RingElem((self.val + other.val) % self.MODULUS, self.MODULUS)
        raise ValueError("Unsupported operand type for +")

    def __sub__(self, other):
        if isinstance(other, RingElem):
            return RingElem((self.val - other.val) % self.MODULUS, self.MODULUS)
        raise ValueError("Unsupported operand type for -")

    def __mul__(self, other):
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

    @classmethod
    def __init__(cls, mod):
        cls.MODULUS = mod
        cls.ENCODED_SIZE = 8

    @classmethod
    def new_elm(cls, val):
        return RingElem(val, cls.MODULUS)

    @classmethod
    def zero(cls):
        return RingElem(0, cls.MODULUS)

    @classmethod
    def one(cls):
        return RingElem(1, cls.MODULUS)

    @classmethod
    def zeros(cls, length: Unsigned) -> Vec[Field]:
        vec = [cls.zero() for _ in range(length)]
        return vec


if __name__ == '__main__':
    r = Ring(2**6)
    el_1 = r.new_elm(42)
    el_2 = r.new_elm(20)
    sum = el_1 + el_2

    assert el_1.as_unsigned() == 42
    assert el_2.as_unsigned() == 20
    assert sum.as_unsigned() == 62

    sum += r.new_elm(10)

    assert sum.as_unsigned() == 8
    assert (r.new_elm(-1) * sum).as_unsigned() == 56
