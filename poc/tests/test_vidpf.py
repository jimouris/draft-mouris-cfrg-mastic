import unittest
from random import randrange

from vdaf_poc.common import gen_rand, vec_add
from vdaf_poc.field import Field2, Field128

from vidpf import Vidpf


class Test(unittest.TestCase):

    def test(self):
        vidpf = Vidpf(Field128, 2, 1)
        self.assertEqual(vidpf.BITS, 2)
        self.assertEqual(vidpf.VALUE_LEN, 1)

        nonce = gen_rand(vidpf.NONCE_SIZE)
        # alpha values from different users
        measurements = [0b10, 0b00, 0b11, 0b01, 0b11]
        beta = [vidpf.field(2)]
        prefixes = [0b0, 0b1]
        level = 0

        out = [Field128.zeros(vidpf.VALUE_LEN + 1)] * len(prefixes)
        for measurement in measurements:
            rand = gen_rand(vidpf.RAND_SIZE)
            (correction_words, keys) = vidpf.gen(
                measurement, beta, nonce, rand)

            proofs = []
            for agg_id in range(2):
                (_beta_share, out_share, proof) = vidpf.eval(
                    agg_id,
                    correction_words,
                    keys[agg_id],
                    level,
                    prefixes,
                    nonce,
                )
                proofs.append(proof)

                for i in range(len(prefixes)):
                    out[i] = vec_add(out[i], out_share[i])
            self.assertTrue(vidpf.verify(proofs[0], proofs[1]))

        self.assertEqual(out, [
            [Field128(2), Field128(4)],  # [counter, value]
            [Field128(3), Field128(6)],
        ])

        vidpf = Vidpf(Field128, 16, 1)
        # `alpha` values from different Clients.
        measurements = [
            0b1111000011110000,
            0b1111000011110001,
            0b1111000011110010,
            0b0000010011110010,
        ]
        beta = [Field128(1)]
        prefixes = [
            0b000001,
            0b111100,
            0b111101,
        ]
        level = 5

        out = [Field128.zeros(vidpf.VALUE_LEN + 1)] * len(prefixes)
        for measurement in measurements:
            rand = gen_rand(vidpf.RAND_SIZE)
            (correction_words, keys) = vidpf.gen(
                measurement, beta, nonce, rand)

            proofs = []
            for agg_id in range(2):
                (_beta_share, out_share, proof) = vidpf.eval(
                    agg_id,
                    correction_words,
                    keys[agg_id],
                    level,
                    prefixes,
                    nonce,
                )
                proofs.append(proof)

                for i in range(len(prefixes)):
                    out[i] = vec_add(out[i], out_share[i])
            self.assertTrue(vidpf.verify(proofs[0], proofs[1]))

        self.assertEqual(out, [
            [Field128(1), Field128(1)],
            [Field128(3), Field128(3)],
            [Field128(0), Field128(0)],
        ])

    def test_malformed_key(self):
        vidpf = Vidpf(Field128, 5, 1)
        nonce = gen_rand(vidpf.NONCE_SIZE)
        rand = gen_rand(vidpf.RAND_SIZE)
        (public_share, keys) = vidpf.gen(0, [Field128(1)], nonce, rand)

        # Tweak some random server's key.
        malformed_agg_id = randrange(0, 2)
        malformed = bytearray(keys[malformed_agg_id])
        malformed[0] ^= 1
        keys[malformed_agg_id] = bytes(malformed)

        for level in range(vidpf.BITS):
            prefixes = tuple(range(2**level))
            proofs = []
            for agg_id in range(2):
                (_beta_share, _out_share, proof) = vidpf.eval(
                    agg_id,
                    public_share,
                    keys[agg_id],
                    level,
                    prefixes,
                    nonce,
                )
                proofs.append(proof)
            self.assertFalse(vidpf.verify(proofs[0], proofs[1]))

    def test_malformed_correction_word_seed(self):
        vidpf = Vidpf(Field128, 5, 1)
        nonce = gen_rand(vidpf.NONCE_SIZE)
        rand = gen_rand(vidpf.RAND_SIZE)
        (public_share, keys) = vidpf.gen(0, [Field128(1)], nonce, rand)

        # Tweak the seed of some correction word.
        malformed_level = randrange(vidpf.BITS)
        (seed_cw, ctrl_cw, w_cw, proof_cw) = public_share[malformed_level]
        malformed = bytearray(seed_cw)
        malformed[0] ^= 1
        public_share[malformed_level] = (malformed, ctrl_cw, w_cw, proof_cw)

        # The tweak doesn't impact the computation until we reach the level
        # with the malformed correction word.
        for level in range(malformed_level, vidpf.BITS):
            prefixes = tuple(range(2**level))
            proofs = []
            for agg_id in range(2):
                (_beta_share, _out_share, proof) = vidpf.eval(
                    agg_id,
                    public_share,
                    keys[agg_id],
                    level,
                    prefixes,
                    nonce,
                )
                proofs.append(proof)
            self.assertFalse(vidpf.verify(proofs[0], proofs[1]))

    def test_malformed_correction_word_ctrl(self):
        vidpf = Vidpf(Field128, 5, 1)
        nonce = gen_rand(vidpf.NONCE_SIZE)
        rand = gen_rand(vidpf.RAND_SIZE)
        (public_share, keys) = vidpf.gen(0, [Field128(1)], nonce, rand)

        # Tweak some control bit of some correction word.
        malformed_level = randrange(vidpf.BITS)
        (seed_cw, ctrl_cw, w_cw, proof_cw) = public_share[malformed_level]
        malformed = ctrl_cw.copy()
        malformed[randrange(2)] += Field2(1)
        public_share[malformed_level] = (seed_cw, malformed, w_cw, proof_cw)

        # The tweak doesn't impact the computation until we reach the level
        # with the malformed correction word.
        for level in range(malformed_level, vidpf.BITS):
            prefixes = tuple(range(2**level))
            proofs = []
            for agg_id in range(2):
                (_beta_share, _out_share, proof) = vidpf.eval(
                    agg_id,
                    public_share,
                    keys[agg_id],
                    level,
                    prefixes,
                    nonce,
                )
                proofs.append(proof)
            self.assertFalse(vidpf.verify(proofs[0], proofs[1]))

    def test_malformed_correction_word_payload(self):
        vidpf = Vidpf(Field128, 5, 1)
        nonce = gen_rand(vidpf.NONCE_SIZE)
        rand = gen_rand(vidpf.RAND_SIZE)
        (public_share, keys) = vidpf.gen(0, [Field128(1)], nonce, rand)

        # Tweak the payload of some correction word.
        malformed_level = randrange(vidpf.BITS)
        (seed_cw, ctrl_cw, w_cw, proof_cw) = public_share[malformed_level]
        malformed = w_cw.copy()
        malformed[randrange(vidpf.VALUE_LEN)] += Field128(1)
        public_share[malformed_level] = (seed_cw, ctrl_cw, malformed, proof_cw)

        # The tweak doesn't impact the computation until we reach the level
        # with the malformed correction word.
        for level in range(malformed_level, vidpf.BITS):
            prefixes = tuple(range(2**level))
            proofs = []
            for agg_id in range(2):
                (_beta_share, _out_share, proof) = vidpf.eval(
                    agg_id,
                    public_share,
                    keys[agg_id],
                    level,
                    prefixes,
                    nonce,
                )
                proofs.append(proof)
            self.assertFalse(vidpf.verify(proofs[0], proofs[1]))

    # TODO Figure out we expect the proof to be malleable or if there's a bug
    # in our code. This test demonstrates that we can tweak the proof of a
    # correction word without being detected.
    @unittest.skip("this test is known to fail")
    def test_malformed_correction_word_proof(self):
        vidpf = Vidpf(Field128, 5, 1)
        nonce = gen_rand(vidpf.NONCE_SIZE)
        rand = gen_rand(vidpf.RAND_SIZE)
        (public_share, keys) = vidpf.gen(0, [Field128(1)], nonce, rand)

        # Tweak the proof of some correction word.
        malformed_level = randrange(vidpf.BITS)
        (seed_cw, ctrl_cw, w_cw, proof_cw) = public_share[malformed_level]
        malformed = bytearray(proof_cw)
        malformed[0] ^= 1
        public_share[malformed_level] = (seed_cw, ctrl_cw, w_cw, malformed)

        # The tweak doesn't impact the computation until we reach the level
        # with the malformed correction word.
        for level in range(malformed_level, vidpf.BITS):
            prefixes = tuple(range(2**level))
            proofs = []
            for agg_id in range(2):
                (_beta_share, _out_share, proof) = vidpf.eval(
                    agg_id,
                    public_share,
                    keys[agg_id],
                    level,
                    prefixes,
                    nonce,
                )
                proofs.append(proof)
            self.assertFalse(vidpf.verify(proofs[0], proofs[1]))
