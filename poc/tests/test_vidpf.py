import unittest

from vdaf_poc.common import gen_rand, vec_add
from vdaf_poc.field import Field128

from vidpf import Vidpf


class Test(unittest.TestCase):

    def test(self):
        vidpf = Vidpf(Field128, 2, 1)
        self.assertEqual(vidpf.BITS, 2)
        self.assertEqual(vidpf.VALUE_LEN, 1)

        binder = b'some nonce'
        # alpha values from different users
        measurements = [0b10, 0b00, 0b11, 0b01, 0b11]
        beta = [vidpf.field(2)]
        prefixes = [0b0, 0b1]
        level = 0

        out = [Field128.zeros(vidpf.VALUE_LEN + 1)] * len(prefixes)
        for measurement in measurements:
            rand = gen_rand(vidpf.RAND_SIZE)
            (init_seed, (correction_words, cs_proofs)) = vidpf.gen(
                measurement, beta, binder, rand)

            proofs = []
            for agg_id in range(2):
                (_beta_share, out_share, proof) = vidpf.eval(
                    agg_id,
                    correction_words,
                    cs_proofs,
                    init_seed[agg_id],
                    level,
                    prefixes,
                    binder,
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
            (init_seed, (correction_words, cs_proofs)) = vidpf.gen(
                measurement, beta, binder, rand)

            proofs = []
            for agg_id in range(2):
                (_beta_share, out_share, proof) = vidpf.eval(
                    agg_id,
                    correction_words,
                    cs_proofs,
                    init_seed[agg_id],
                    level,
                    prefixes,
                    binder,
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
