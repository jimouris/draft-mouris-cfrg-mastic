"""Definitions of ring used in this spec."""

from __future__ import annotations
import hashlib


class Ring:
    """The base class for ring elements."""
    MODULUS: Unsigned
    ENCODED_SIZE: Unsigned

    def __init__(self, val):
        self.val = val % self.MODULUS

    def __add__(self, other):
        if self.MODULUS != other.MODULUS:
            raise ValueError("Different moduli in add:", self.MODULUS, other.MODULUS)
        if isinstance(other, self.__class__):
            return self.__class__(self.val + other.val)
        raise ValueError("Unsupported operand type for +")

    def __sub__(self, other):
        if self.MODULUS != other.MODULUS:
            raise ValueError("Different moduli in sub:", self.MODULUS, other.MODULUS)
        if isinstance(other, self.__class__):
            return self.__class__(self.val - other.val)
        raise ValueError("Unsupported operand type for -")

    def __mul__(self, other):
        if self.MODULUS != other.MODULUS:
            raise ValueError("Different moduli in mul:", self.MODULUS, other.MODULUS)
        if isinstance(other, self.__class__):
            return self.__class__(self.val * other.val)
        raise ValueError("Unsupported operand type for *")

    def __neg__(self):
        return self.__class__((-self.val) % self.MODULUS)

    def __eq__(self, other):
        if isinstance(other, self.__class__):
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

    @classmethod
    def zeros(Ring, length: Unsigned) -> list[Ring]:
        vec = [Ring(0) for _ in range(length)]
        return vec

    @classmethod
    def ones(Ring, length: Unsigned) -> list[Ring]:
        vec = [Ring(1) for _ in range(length)]
        return vec


class Ring2(Ring):
    """The base class for 16-bit ring."""
    MODULUS = 2
    ENCODED_SIZE = 1

    def __str__(self):
        return 'Ring2(' + str(self.MODULUS) + ')'

class Ring16(Ring):
    """The base class for 16-bit ring."""
    MODULUS = 2**16
    ENCODED_SIZE = 2

    def __str__(self):
        return 'Ring16(' + str(self.MODULUS) + ')'



def main():
    '''Run some tests.'''
    class Ring6(Ring):
        MODULUS = 2**6
        ENCODED_SIZE = 1
    r = Ring6

    print(r, 'tests')
    el_1 = r(42)
    el_2 = r(20)
    sum = el_1 + el_2

    assert el_1.as_unsigned() == 42
    assert el_2.as_unsigned() == 20
    assert sum.as_unsigned() == 62

    sum += r(10)

    assert sum.as_unsigned() == 8
    assert (r(-1) * sum).as_unsigned() == 56

    r2 = Ring2
    print(r2, 'tests')
    assert r2(1).as_unsigned() == 1
    assert r2(0).as_unsigned() == 0
    assert r2(1) + r2(1) == r2(0)
    assert r2(1) * r2(1) == r2(1)
    assert -r2(1) == r2(1)
    assert r2(1).conditional_select(b'hello') == b'hello'
    assert r2(0).conditional_select(b'hello') == bytes([0, 0, 0, 0, 0])

    try:
        r2(1) + r.ones(1)
        assert False
    except Exception as e:
        print("Caught error correctly:", str(e))


if __name__ == '__main__':
    main()
