import unittest
from random import randrange

from vdaf_poc.common import from_be_bytes, gen_rand
from vdaf_poc.field import Field64
from vdaf_poc.test_utils import TestVdaf

from mastic import MasticCount, MasticSum, MasticSumVec


class TestValidAggParams(unittest.TestCase):
    def test_is_valid(self) -> None:
        mastic = MasticCount(4)

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


class TestMalformedReport(unittest.TestCase):
    bits = 5

    def run_test(self, modify_report, agg_param, expect_success=False):
        """
        Generate a report, modify it using `modify_report`, then run
        preparation.
        """
        mastic = MasticCount(self.bits)
        ctx = b'some application'
        verify_key = gen_rand(mastic.VERIFY_KEY_SIZE)
        nonce = gen_rand(mastic.NONCE_SIZE)
        rand = gen_rand(mastic.RAND_SIZE)
        measurement = ((True,) * self.bits, True)

        # Generate an invalid report.
        (public_share, input_shares) = modify_report(
            mastic,
            *mastic.shard(
                ctx,
                measurement,
                nonce,
                rand
            ),
        )

        # Attempt preparation w/o the weight check.
        (_prep_state_0, prep_share_0) = mastic.prep_init(
            verify_key,
            ctx,
            0,
            agg_param,
            nonce,
            public_share,
            input_shares[0],
        )
        (_prep_state_1, prep_share_1) = mastic.prep_init(
            verify_key,
            ctx,
            1,
            agg_param,
            nonce,
            public_share,
            input_shares[1],
        )

        def test():
            return mastic.prep_shares_to_prep(ctx, agg_param,
                                              [prep_share_0, prep_share_1])
        if expect_success:
            test()
        else:
            with self.assertRaises(Exception):
                test()

    def test_malformed_correction_word_payload_counter(self):
        malformed_level = randrange(self.bits)

        def modify_report(mastic, public_share, input_shares):
            """
            Tweak the counter of the payload of some correction word.
            """
            (seed_cw, ctrl_cw, w_cw, proof_cw) = public_share[malformed_level]
            malformed = w_cw.copy()
            malformed[0] += Field64(1)
            public_share[malformed_level] = (
                seed_cw, ctrl_cw, malformed, proof_cw)
            return (public_share, input_shares)

        # We expect the counter check to fail for the tweaked level and all
        # subsequent levels.
        for level in range(malformed_level, self.bits):
            agg_param = (level, ((True,) * (level+1),), False)
            self.run_test(modify_report, agg_param)

    def test_malformed_correction_word_payload_weight(self):
        malformed_level = randrange(self.bits)

        def modify_report(mastic, public_share, input_shares):
            """
            Tweak the weight of the payload of some correction word.
            """
            (seed_cw, ctrl_cw, w_cw, proof_cw) = public_share[malformed_level]
            malformed = w_cw.copy()
            malformed[1] += Field64(1)
            public_share[malformed_level] = (
                seed_cw, ctrl_cw, malformed, proof_cw)
            return (public_share, input_shares)

        # For all but the first level, tweaking a correction word weight should
        # cause the payload check to fail.
        for level in range(malformed_level, self.bits):
            agg_param = (level, ((True,) * (level+1),), False)
            self.run_test(modify_report, agg_param)

    def test_malformed_weight_share(self):
        def modify_report(mastic, public_share, input_shares):
            """Tweak the leader's weight share."""
            input_shares[0].weight_share[0] += Field64(1)
            return (public_share, input_shares)

        # The payload check should fail at every level.
        for level in range(self.bits):
            agg_param = (level, ((True,) * (level+1),), False)
            self.run_test(modify_report, agg_param)


class TestMastic(TestVdaf):
    def test_count(self):
        mastic = MasticCount(2)
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

        mastic = MasticCount(2)
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

        mastic = MasticCount(16)
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

        mastic = MasticCount(256)
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

        mastic = MasticCount(2)
        self.run_vdaf_test(
            MasticCount(2),
            (1, ((False, False),), True),
            [
                ((True, True), True),
            ],
            [0],
        )

    def test_sum(self):
        mastic = MasticSum(2, 2**3 - 1)
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

        mastic = MasticSum(2, 2**2 - 1)
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

        mastic = MasticSum(16, 1)
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

        mastic = MasticSum(256, 2**8 - 1)
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
        mastic = MasticSumVec(16, 3, 1, 1)
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
