import unittest

from vdaf_poc.common import from_be_bytes
from vdaf_poc.field import Field64
from vdaf_poc.flp_bbcggi19 import Count, Sum
from vdaf_poc.test_utils import TestVdaf

from mastic import Mastic


class TestValidAggParams(unittest.TestCase):
    def test(self):
        mastic = Mastic(4, Count(Field64))

        assert mastic.is_valid(
            (0, (0,), True),
            [],
        )

        assert mastic.is_valid(
            (2, (0b100,), True),
            [],
        )

        # Expect invalid because we never do the range check.
        assert not mastic.is_valid(
            (0, (0,), False),
            [],
        )

        assert mastic.is_valid(
            (1, (0b10,), False),
            [
                (0, (0,), True),
            ],
        )

        # Expect invalid because we do the range check twice.
        assert not mastic.is_valid(
            (1, (0b10,), True),
            [
                (0, (0,), True),
            ],
        )

        # Expect invalid because we don't do the range check at the first level.
        assert not mastic.is_valid(
            (1, (0b10,), True),
            [
                (0, (0,), False),
            ],
        )

        # Expect invalid because we never do the range check.
        assert not mastic.is_valid(
            (1, (0b10,), False),
            [
                (0, (0,), False),
            ],
        )

        # Expect invalid because the level decreases.
        assert not mastic.is_valid(
            (1, (0b10,), False),
            [
                (2, (0b100,), True),
            ],
        )

        assert mastic.is_valid(
            (2, (0b101,), False),
            [
                (2, (0b100,), True),
            ],
        )


class TestMastic(TestVdaf):

    def test_count(self):
        self.run_vdaf_test(
            Mastic(2, Count(Field64)),
            (0, (0b0, 0b1), True),
            [
                (0b10, 1),
                (0b00, 1),
                (0b11, 1),
                (0b01, 1),
                (0b11, 1),
            ],
            [2, 3],
        )

        self.run_vdaf_test(
            Mastic(2, Count(Field64)),
            (1, (0b00, 0b01), True),
            [
                (0b10, 1),
                (0b00, 1),
                (0b11, 1),
                (0b01, 1),
                (0b01, 0),
            ],
            [1, 1],
        )

        self.run_vdaf_test(
            Mastic(16, Count(Field64)),
            (14, (0b111100001111000,), True),
            [
                (0b1111000011110000, 0),
                (0b1111000011110001, 1),
                (0b0111000011110000, 0),
                (0b1111000011110010, 1),
                (0b1111000000000000, 0),
            ],
            [1],
        )

        self.run_vdaf_test(
            Mastic(256, Count(Field64)),
            (
                63,
                (
                    from_be_bytes(b'00000000'),
                    from_be_bytes(b'01234567'),
                ),
                True,
            ),
            [
                (from_be_bytes(b'0123456789abcdef0123456789abcdef'), 1),
                (from_be_bytes(b'01234567890000000000000000000000'), 1),
            ],
            [0, 2],
        )

    def test_sum(self):
        self.run_vdaf_test(
            Mastic(2, Sum(Field64, 2**3 - 1)),
            (0, (0b0, 0b1), True),
            [
                (0b10, 1),
                (0b00, 6),
                (0b11, 7),
                (0b01, 5),
                (0b11, 2),
            ],
            [11, 10],
        )

        self.run_vdaf_test(
            Mastic(2, Sum(Field64, 2**2 - 1)),
            (1, (0b00, 0b01), True),
            [
                (0b10, 3),
                (0b00, 2),
                (0b11, 0),
                (0b01, 1),
                (0b01, 2),
            ],
            [2, 3],
        )

        self.run_vdaf_test(
            Mastic(16, Sum(Field64, 1)),
            (14, (0b111100001111000,), True),
            [
                (0b1111000011110000, 0),
                (0b1111000011110001, 1),
                (0b0111000011110000, 0),
                (0b1111000011110010, 1),
                (0b1111000000000000, 0),
            ],
            [1],
        )

        self.run_vdaf_test(
            Mastic(256, Sum(Field64, 2**8 - 1)),
            (
                63,
                (
                    from_be_bytes(b'00000000'),
                    from_be_bytes(b'01234567'),
                ),
                True,
            ),
            [
                (from_be_bytes(b'0123456789abcdef0123456789abcdef'), 121),
                (from_be_bytes(b'01234567890000000000000000000000'), 6),
            ],
            [0, 127],
        )
