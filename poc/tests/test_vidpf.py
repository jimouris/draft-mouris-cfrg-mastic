import unittest
from random import randrange

from vdaf_poc.common import gen_rand, vec_add
from vdaf_poc.field import Field128

from vidpf import ONEHOT_PROOF_INIT, PrefixTreeEntry, PrefixTreeIndex, Vidpf


class Test(unittest.TestCase):

    def test_eval_invariants(self):
        vidpf = Vidpf(Field128, 5, 1)
        nonce = gen_rand(vidpf.NONCE_SIZE)
        rand = gen_rand(vidpf.RAND_SIZE)
        alpha = randrange(2 ** vidpf.BITS)
        (pub, keys) = vidpf.gen(alpha, [Field128(1)], nonce, rand)

        # On path
        node = [
            PrefixTreeEntry.root(keys[0], False),
            PrefixTreeEntry.root(keys[1], True),
        ]
        proof = [ONEHOT_PROOF_INIT, ONEHOT_PROOF_INIT]
        for i in range(vidpf.BITS):
            idx = PrefixTreeIndex(alpha >> (vidpf.BITS - i - 1), i)
            (node[0], proof[0]) = vidpf.eval_next(
                node[0], proof[0], pub[i], nonce, idx)
            (node[1], proof[1]) = vidpf.eval_next(
                node[1], proof[1], pub[i], nonce, idx)

            # Each aggregator should end up with a different seed.
            self.assertTrue(node[0].seed != node[1].seed)

            # The control bits should be secret shares of one, i.e., the
            # control bit should be set for one and only one of the
            # aggregators.
            self.assertTrue(node[0].ctrl != node[1].ctrl)

            # One of the aggregators corrects the node proof, which means both
            # should compute the same node proof.
            self.assertEqual(proof[0], proof[1])

        # Off path
        node = [
            PrefixTreeEntry.root(keys[0], False),
            PrefixTreeEntry.root(keys[1], True),
        ]
        proof = [ONEHOT_PROOF_INIT, ONEHOT_PROOF_INIT]
        for i in range(vidpf.BITS):
            # We want an off-path index. The sibling of the on-path prefix is
            # an off-path prefix.
            idx = PrefixTreeIndex(alpha >> (vidpf.BITS - i - 1), i).sibling()
            (node[0], proof[0]) = vidpf.eval_next(
                node[0], proof[0], pub[i], nonce, idx)
            (node[1], proof[1]) = vidpf.eval_next(
                node[1], proof[1], pub[i], nonce, idx)

            # The aggregators should compute the same seed.
            self.assertEqual(node[0].seed, node[1].seed)

            # The control bits should be secret shares of zero, i.e., either
            # both have the bit set or neither does.
            self.assertTrue(node[0].ctrl == node[1].ctrl)

            # Either both aggregators correct their node proof or neither does.
            self.assertEqual(proof[0], proof[1])

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

    def test_exhuastive(self):
        """
        Evaluate all possible prefixes and ensure the on-path prefixes (and
        only those prefixes) evaluate to `beta`.
        """
        vidpf = Vidpf(Field128, 5, 1)
        alpha = randrange(2**vidpf.BITS)
        nonce = gen_rand(vidpf.NONCE_SIZE)
        rand = gen_rand(vidpf.RAND_SIZE)
        (pub, keys) = vidpf.gen(alpha, [Field128(13)], nonce, rand)

        for level in range(vidpf.BITS):
            prefixes = tuple(range(2**level))
            out_shares = []
            proofs = []
            for agg_id in range(2):
                (_beta_share, out_share, proof) = vidpf.eval(
                    agg_id,
                    pub,
                    keys[agg_id],
                    level,
                    prefixes,
                    nonce,
                )
                out_shares.append(out_share)
                proofs.append(proof)
            for prefix in prefixes:
                out = vec_add(out_shares[0][prefix], out_shares[1][prefix])
                if vidpf.is_prefix(prefix, alpha, level):
                    expectedOut = [Field128(1), Field128(13)]
                else:
                    expectedOut = [Field128(0), Field128(0)]
                self.assertEqual(out, expectedOut)
            self.assertTrue(vidpf.verify(proofs[0], proofs[1]))

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
        malformed_index = randrange(2)
        malformed[malformed_index] = not malformed[malformed_index]
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

    def test_malformed_correction_word_proof(self):
        vidpf = Vidpf(Field128, 5, 1)
        nonce = gen_rand(vidpf.NONCE_SIZE)
        rand = gen_rand(vidpf.RAND_SIZE)
        alpha = randrange(2 ** vidpf.BITS)
        (pub, keys) = vidpf.gen(alpha, [Field128(1)], nonce, rand)

        # Tweak the proof of some correction word.
        malformed_level = randrange(vidpf.BITS)
        (seed_cw, ctrl_cw, w_cw, proof_cw) = pub[malformed_level]
        malformed = bytearray(proof_cw)
        malformed[0] ^= 1
        pub[malformed_level] = (seed_cw, ctrl_cw, w_cw, malformed)

        # The tweak doesn't impact the computation until we reach the level
        # with the malformed correction word.
        for level in range(malformed_level, vidpf.BITS):
            prefixes = tuple(range(2 ** level))
            for prefix in prefixes:
                valid = vidpf.verify(
                    vidpf.eval(0, pub, keys[0], level, [prefix], nonce)[2],
                    vidpf.eval(1, pub, keys[1], level, [prefix], nonce)[2],
                )

                # If the prefix is on path, then we expect the proofs to be
                # different. This is because exactly one of the aggregators
                # corrects the node proof: if correction word is not malformed,
                # then the corrected node proof will equal the node proof
                # computed by its co-aggregator; but since the correction word
                # is malformed, they will always compute different node proofs.
                #
                # If the prefix has no prefix in common with `alpha`, then we
                # expect the proofs to be equal. Both aggregators will correct
                # the node proof or neither will, and since they compute the
                # same seed, we expect them to compute the same node proof.
                #
                # However if the prefix does have a prefix in common with
                # `alpha`, then the proof we start with might not match, in
                # which case the proof for the off-path segment will also not
                # match.
                #
                # NOTE This points to an attack on privacy. If the attacker
                # controls the public share consumed by the honest aggregator,
                # whether the proofs match will tell it if a given prefix is on
                # or off path. It is therefore crucial to ensure that the
                # honest client and honest aggregator agree on the public
                # share.
                if vidpf.is_prefix(prefix, alpha, level):
                    self.assertFalse(valid)
