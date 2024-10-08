import unittest

from vdaf_poc.common import from_be_bytes
from vdaf_poc.field import Field64, Field128
from vdaf_poc.flp_bbcggi19 import Count, Sum, SumVec
from vdaf_poc.test_utils import TestVdaf

from mastic import Mastic


class TestValidAggParams(unittest.TestCase):
    def test_is_valid(self) -> None:
        mastic = Mastic(4, Count(Field64))

        self.assertTrue(mastic.is_valid(
            (0, ((False,),), True),
            [],
        ))

        self.assertTrue(mastic.is_valid(
            (2, ((True, False, False,),), True),
            [],
        ))

        # Expect invalid because we never do the range check.
        self.assertFalse(mastic.is_valid(
            (0, ((False,),), False),
            [],
        ))

        self.assertTrue(mastic.is_valid(
            (1, ((False, True,),), False),
            [
                (0, ((False,),), True),
            ],
        ))

        # Expect invalid because we do the range check twice.
        self.assertFalse(mastic.is_valid(
            (1, ((False, True,),), True),
            [
                (0, ((False,),), True),
            ],
        ))

        # Expect invalid because we don't do the range check at the first level.
        self.assertFalse(mastic.is_valid(
            (1, ((False, True,),), True),
            [
                (0, ((False,),), False),
            ],
        ))

        # Expect invalid because we never do the range check.
        self.assertFalse(mastic.is_valid(
            (1, ((True, False,),), False),
            [
                (0, ((False,),), False),
            ],
        ))

        # Expect invalid because the level decreases.
        self.assertFalse(mastic.is_valid(
            (1, ((True, False,),), False),
            [
                (2, ((True, False, False,),), True),
            ],
        ))


class TestMastic(TestVdaf):
    def test_count(self):
        mastic = Mastic(2, Count(Field64))
        self.run_vdaf_test(
            mastic,
            (
                0,
                (
                    mastic.vidpf.test_index_from_int(0b0, 1),
                    mastic.vidpf.test_index_from_int(0b1, 1),
                ),
                True,
            ),
            [
                (mastic.vidpf.test_index_from_int(0b10, 2), 1),
                (mastic.vidpf.test_index_from_int(0b00, 2), 1),
                (mastic.vidpf.test_index_from_int(0b11, 2), 1),
                (mastic.vidpf.test_index_from_int(0b01, 2), 1),
                (mastic.vidpf.test_index_from_int(0b11, 2), 1),
            ],
            [2, 3],
        )

        mastic = Mastic(2, Count(Field64))
        self.run_vdaf_test(
            mastic,
            (1, (mastic.vidpf.test_index_from_int(0b00, 2),
             mastic.vidpf.test_index_from_int(0b01, 2)), True),
            [
                (mastic.vidpf.test_index_from_int(0b10, 2), 1),
                (mastic.vidpf.test_index_from_int(0b00, 2), 1),
                (mastic.vidpf.test_index_from_int(0b11, 2), 1),
                (mastic.vidpf.test_index_from_int(0b01, 2), 1),
                (mastic.vidpf.test_index_from_int(0b01, 2), 0),
            ],
            [1, 1],
        )

        mastic = Mastic(16, Count(Field64))
        self.run_vdaf_test(
            mastic,
            (14, (mastic.vidpf.test_index_from_int(0b111100001111000, 15),), True),
            [
                (mastic.vidpf.test_index_from_int(0b1111000011110000, 16), 0),
                (mastic.vidpf.test_index_from_int(0b1111000011110001, 16), 1),
                (mastic.vidpf.test_index_from_int(0b0111000011110000, 16), 0),
                (mastic.vidpf.test_index_from_int(0b1111000011110010, 16), 1),
                (mastic.vidpf.test_index_from_int(0b1111000000000000, 16), 0),
            ],
            [1],
        )

        mastic = Mastic(256, Count(Field64))
        self.run_vdaf_test(
            mastic,
            (
                63,
                (
                    mastic.vidpf.test_index_from_int(
                        from_be_bytes(b'00000000'), 64),
                    mastic.vidpf.test_index_from_int(
                        from_be_bytes(b'01234567'), 64),
                ),
                True,
            ),
            [
                (mastic.vidpf.test_index_from_int(from_be_bytes(
                    b'0123456789abcdef0123456789abcdef'), 256), 1),
                (mastic.vidpf.test_index_from_int(from_be_bytes(
                    b'01234567890000000000000000000000'), 256), 1),
            ],
            [0, 2],
        )

    def test_sum(self):
        mastic = Mastic(2, Sum(Field64, 2**3 - 1))
        self.run_vdaf_test(
            mastic,
            (0, (mastic.vidpf.test_index_from_int(0b0, 1),
             mastic.vidpf.test_index_from_int(0b1, 1)), True),
            [
                (mastic.vidpf.test_index_from_int(0b10, 2), 1),
                (mastic.vidpf.test_index_from_int(0b00, 2), 6),
                (mastic.vidpf.test_index_from_int(0b11, 2), 7),
                (mastic.vidpf.test_index_from_int(0b01, 2), 5),
                (mastic.vidpf.test_index_from_int(0b11, 2), 2),
            ],
            [11, 10],
        )

        mastic = Mastic(2, Sum(Field64, 2**2 - 1))
        self.run_vdaf_test(
            mastic,
            (1, (mastic.vidpf.test_index_from_int(0b00, 2),
             mastic.vidpf.test_index_from_int(0b01, 2)), True),
            [
                (mastic.vidpf.test_index_from_int(0b10, 2), 3),
                (mastic.vidpf.test_index_from_int(0b00, 2), 2),
                (mastic.vidpf.test_index_from_int(0b11, 2), 0),
                (mastic.vidpf.test_index_from_int(0b01, 2), 1),
                (mastic.vidpf.test_index_from_int(0b01, 2), 2),
            ],
            [2, 3],
        )

        mastic = Mastic(16, Sum(Field64, 1))
        self.run_vdaf_test(
            mastic,
            (14, (mastic.vidpf.test_index_from_int(0b111100001111000, 15),), True),
            [
                (mastic.vidpf.test_index_from_int(0b1111000011110000, 16), 0),
                (mastic.vidpf.test_index_from_int(0b1111000011110001, 16), 1),
                (mastic.vidpf.test_index_from_int(0b0111000011110000, 16), 0),
                (mastic.vidpf.test_index_from_int(0b1111000011110010, 16), 1),
                (mastic.vidpf.test_index_from_int(0b1111000000000000, 16), 0),
            ],
            [1],
        )

        mastic = Mastic(256, Sum(Field64, 2**8 - 1))
        self.run_vdaf_test(
            mastic,
            (
                63,
                (
                    mastic.vidpf.test_index_from_int(
                        from_be_bytes(b'00000000'), 64),
                    mastic.vidpf.test_index_from_int(
                        from_be_bytes(b'01234567'), 64),
                ),
                True,
            ),
            [
                (mastic.vidpf.test_index_from_int(from_be_bytes(
                    b'0123456789abcdef0123456789abcdef'), 256), 121),
                (mastic.vidpf.test_index_from_int(from_be_bytes(
                    b'01234567890000000000000000000000'), 256), 6),
            ],
            [0, 127],
        )

    def test_sum_vec(self):
        mastic = Mastic(16, SumVec(Field128, 3, 1, 1))
        self.run_vdaf_test(
            mastic,
            (14, (mastic.vidpf.test_index_from_int(0b111100001111000, 15),), True),
            [
                (mastic.vidpf.test_index_from_int(
                    0b1111000011110000, 16), [0, 0, 1]),
                (mastic.vidpf.test_index_from_int(
                    0b1111000011110001, 16), [0, 1, 0]),
                (mastic.vidpf.test_index_from_int(
                    0b0111000011110000, 16), [0, 1, 1]),
                (mastic.vidpf.test_index_from_int(
                    0b1111000011110010, 16), [1, 0, 0]),
                (mastic.vidpf.test_index_from_int(
                    0b1111000000000000, 16), [1, 0, 1]),
            ],
            [[0, 1, 1]],
        )
