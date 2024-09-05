"""Verifiable Distributed Point Function (VIDPF)"""

import hashlib
import itertools
from typing import Generic, Sequence, TypeAlias, TypeVar

from vdaf_poc.common import (format_dst, to_le_bytes, vec_add, vec_neg,
                             vec_sub, xor, zeros)
from vdaf_poc.field import Field2, NttField
from vdaf_poc.xof import XofFixedKeyAes128, XofTurboShake128

F = TypeVar("F", bound=NttField)

ROOT_PI_PROOF = hashlib.sha256(b"vidpf root pi proof").digest()

PROOF_SIZE = 32

CorrectionWord: TypeAlias = tuple[bytes, tuple[Field2, Field2], list[F]]


class Vidpf(Generic[F]):
    """A Verifiable Incremental Distributed Point Function (VIDPF)."""

    # Size in bytes of each vidpf key share.
    KEY_SIZE = XofFixedKeyAes128.SEED_SIZE

    # Number of random bytes consumed by the `gen()` algorithm.
    RAND_SIZE = 2 * XofFixedKeyAes128.SEED_SIZE

    def __init__(self, field: type[F], bits: int, value_len: int):
        self.field = field
        self.BITS = bits
        self.VALUE_LEN = value_len

    # TODO Align API with draft-irtf-cfrg-vdaf-12.
    def gen(self,
            alpha: int,
            beta: list[F],
            binder: bytes,
            rand: bytes,
            # TODO Reduce type complexity
            ) -> tuple[list[bytes], tuple[list[CorrectionWord], list[bytes]]]:
        '''
        https://eprint.iacr.org/2023/080.pdf VIDPF.Gen
        '''
        if alpha >= 2**self.BITS:
            raise ValueError("alpha too long")
        if len(rand) != self.RAND_SIZE:
            raise ValueError("randomness has incorrect length")

        init_seed = [
            rand[:XofFixedKeyAes128.SEED_SIZE],
            rand[XofFixedKeyAes128.SEED_SIZE:],
        ]

        # s0^0, s1^0, t0^0, t1^0
        seed = init_seed.copy()
        ctrl = [Field2(0), Field2(1)]
        correction_words = []
        cs_proofs = []
        for i in range(self.BITS):
            node = (alpha >> (self.BITS - i - 1))
            bit = node & 1
            # if x = 0 then keep <- L, lose <- R
            keep, lose = (1, 0) if bit else (0, 1)

            # s_0^L || s_0^R || t_0^L || t_0^R
            (s_0, t_0) = self.extend(seed[0], binder)
            # s_1^L || s_1^R || t_1^L || t_1^R
            (s_1, t_1) = self.extend(seed[1], binder)
            seed_cw = xor(s_0[lose], s_1[lose])
            ctrl_cw = (
                t_0[0] + t_1[0] + Field2(1) + Field2(bit),  # t_c^L
                t_0[1] + t_1[1] + Field2(bit),              # t_c^R
            )

            (seed[0], w_0) = self.convert(
                correct(s_0[keep], seed_cw, ctrl[0]), binder)
            (seed[1], w_1) = self.convert(
                correct(s_1[keep], seed_cw, ctrl[1]), binder)
            ctrl[0] = correct(t_0[keep], ctrl_cw[keep], ctrl[0])  # t0'
            ctrl[1] = correct(t_1[keep], ctrl_cw[keep], ctrl[1])  # t1'

            w_cw = vec_add(vec_sub([self.field(1)] + beta, w_0), w_1)
            mask = self.field(1) - self.field(2) * \
                self.field(ctrl[1].as_unsigned())
            for j in range(len(w_cw)):
                w_cw[j] *= mask

            # Compute hashes for level i
            cs_proofs.append(xor(
                self.next_cs_proof(node, i, seed[0]),
                self.next_cs_proof(node, i, seed[1]),
            ))
            correction_words.append((seed_cw, ctrl_cw, w_cw))

        return (init_seed, (correction_words, cs_proofs))

    # TODO Align API with draft-irtf-cfrg-vdaf-12.
    def eval(self,
             agg_id: int,
             correction_words: list[CorrectionWord],
             cs_proofs: list[bytes],
             init_seed: bytes,
             level: int,
             prefixes: Sequence[int],
             binder: bytes
             ) -> tuple[list[F], list[list[F]], bytes]:
        if agg_id >= 2:
            raise ValueError("invalid aggregator ID")
        if level >= self.BITS:
            raise ValueError("level too deep")
        if len(set(prefixes)) != len(prefixes):
            raise ValueError("candidate prefixes are non-unique")

        # Compute the Aggregator's share of the prefix tree and the one-hot
        # proof (`pi_proof`).
        #
        # Implementation note: We can save computation by storing
        # `prefix_tree_share` across `eval()` calls for the same report.
        pi_proof = ROOT_PI_PROOF
        # TODO Reduce type complexity
        prefix_tree_share: dict[tuple[int, int],
                                tuple[bytes, Field2, list[F], bytes]] = {}
        for prefix in prefixes:
            if prefix >= 2 ** (level+1):
                raise ValueError("prefix too long")

            # The Aggregator's output share is the value of a node of
            # the IDPF tree at the given `level`. The node's value is
            # computed by traversing the path defined by the candidate
            # `prefix`. Each node in the tree is represented by a seed
            # (`seed`) and a set of control bits (`ctrl`).
            seed = init_seed
            ctrl = Field2(agg_id)
            for current_level in range(level+1):
                node = prefix >> (level - current_level)
                for s in [0, 1]:
                    # Compute the value for the node `node` and its sibling
                    # `node ^ s`. The latter is used for computing the path
                    # proof.
                    if not prefix_tree_share.get((node ^ s, current_level)):
                        prefix_tree_share[(node ^ s, current_level)] = self.eval_next(
                            seed,
                            ctrl,
                            correction_words[current_level],
                            cs_proofs[current_level],
                            current_level,
                            node ^ s,
                            pi_proof,
                            binder,
                        )
                (seed, ctrl, y, pi_proof) = prefix_tree_share[(
                    node, current_level)]

        # Compute the Aggregator's share of `beta`.
        y0 = prefix_tree_share[(0, 0)][2]
        y1 = prefix_tree_share[(1, 0)][2]
        beta_share = vec_add(y0, y1)[1:]  # first element is the counter
        if agg_id == 1:
            beta_share = vec_neg(beta_share)

        # Compute the counter.
        counter = self.field.encode_vec([y0[0] + y1[0] + self.field(agg_id)])

        # Compute the path.
        path = b''
        for prefix in prefixes:
            for current_level in range(level):
                node = prefix >> (level - current_level)
                y = prefix_tree_share[(node,             current_level)][2]
                y0 = prefix_tree_share[(node << 1,       current_level+1)][2]
                y1 = prefix_tree_share[((node << 1) | 1, current_level+1)][2]
                path += self.field.encode_vec(vec_sub(y, vec_add(y0, y1)))

        # Compute the Aggregator's output share.
        out_share = []
        for prefix in prefixes:
            (_seed, _ctrl, y, _pi_proof) = prefix_tree_share[(prefix, level)]
            out_share.append(y if agg_id == 0 else vec_neg(y))

        return (beta_share, out_share, eval_proof(pi_proof, counter, path))

    def eval_next(self, prev_seed, prev_ctrl, correction_word, cs_proof,
                  current_level, node, pi_proof, binder):
        """
        Compute the next node in the VIDPF tree along the path determined by
        a candidate prefix. The next node is determined by `bit`, the bit of
        the prefix corresponding to the next level of the tree.
        """
        (seed_cw, ctrl_cw, w_cw) = correction_word

        # (s^L, s^R), (t^L, t^R) = PRG(s^{i-1})
        (s, t) = self.extend(prev_seed, binder)
        s[0] = xor(s[0], prev_ctrl.conditional_select(seed_cw))  # s^L
        s[1] = xor(s[1], prev_ctrl.conditional_select(seed_cw))  # s^R
        t[0] += ctrl_cw[0] * prev_ctrl  # t^L
        t[1] += ctrl_cw[1] * prev_ctrl  # t^R

        bit = node & 1
        next_ctrl = t[bit]  # t'^i
        (next_seed, w) = self.convert(s[bit],  binder)  # s^i, W^i
        # Implementation note: Here we add the correction word to the
        # output if `next_ctrl` is set. We avoid branching on the value of
        # the control bit in order to reduce side channel leakage.
        y = []
        mask = self.field(next_ctrl.as_unsigned())
        for i in range(len(w)):
            y.append(w[i] + w_cw[i] * mask)

        # pi' = H(x^{<= i} || s^i)
        pi_prime = self.next_cs_proof(node, current_level, next_seed)

        # \pi = \pi xor H(\pi \xor (proof_prime \xor next_ctrl * cs_proof))
        if next_ctrl.as_unsigned() == 1:
            h2 = xor(pi_proof, xor(pi_prime, cs_proof))
        else:
            h2 = xor(pi_proof, pi_prime)
        pi_proof = xor(pi_proof, pi_proof_adjustment(h2))

        return (next_seed, next_ctrl, y, pi_proof)

    def verify(self, proof_0, proof_1):
        '''Check proofs'''
        return proof_0 == proof_1

    def extend(self, seed, binder):
        '''
        Extend seed to (seed_L, t_L, seed_R, t_R)
        '''
        xof = XofFixedKeyAes128(seed, format_dst(1, 0, 0), binder)
        new_seed = [
            xof.next(XofFixedKeyAes128.SEED_SIZE),
            xof.next(XofFixedKeyAes128.SEED_SIZE),
        ]
        bit = xof.next(1)[0]
        ctrl = [Field2(bit & 1), Field2((bit >> 1) & 1)]
        return (new_seed, ctrl)

    def convert(self, seed, binder):
        '''
        Converting seed to a pseudorandom element of G.
        '''
        xof = XofFixedKeyAes128(seed, format_dst(1, 0, 1), binder)
        next_seed = xof.next(XofFixedKeyAes128.SEED_SIZE)
        return (next_seed, xof.next_vec(self.field, 1+self.VALUE_LEN))

    def next_cs_proof(self, node, level, seed):
        binder = to_le_bytes(self.BITS, 2) \
            + to_le_bytes(node, (self.BITS + 7) // 8) \
            + to_le_bytes(level, 2)
        xof = XofTurboShake128(seed, b'vidpf cs proof', binder)
        return xof.next(PROOF_SIZE)

    def encode_public_share(self, public_share):
        # TODO(cjpatton) Align with Poplar1 public share in draft-irtf-cfrg-vdaf-12
        (correction_words, cs_proofs) = public_share
        encoded = bytes()
        control_bits = list(itertools.chain.from_iterable(
            cw[1] for cw in correction_words
        ))
        encoded += pack_bits(control_bits)
        for lvl in range(self.BITS):
            (seed_cw, ctrl_cw, w_cw) = correction_words[lvl]
            encoded += seed_cw
            encoded += self.field.encode_vec(w_cw)
            encoded += cs_proofs[lvl]
        return encoded


def correct(k_0, k_1, ctrl):
    ''' return k_0 if ctrl == 0 else xor(k_0, k_1) '''
    if isinstance(k_0, bytes):
        return xor(k_0, ctrl.conditional_select(k_1))
    if isinstance(k_0, list):  # list of ints or ring elements
        for i in range(len(k_0)):
            k_0[i] += ctrl * k_1[i]
        return k_0
    # int or ring element
    return k_0 + ctrl * k_1


def pi_proof_adjustment(h2):
    xof = XofTurboShake128(
        zeros(XofTurboShake128.SEED_SIZE),
        b'vidpf proof adjustment',
        h2,
    )
    return xof.next(PROOF_SIZE)


def eval_proof(pi_proof, counter, path) -> bytes:
    xof = XofTurboShake128(
        zeros(XofTurboShake128.SEED_SIZE),
        b'vidpf eval proof',
        pi_proof + counter + path,
    )
    return xof.next(PROOF_SIZE)


def pack_bits(bits):
    byte_len = (len(bits) + 7) // 8
    packed = [int(0)] * byte_len
    for i, bit in enumerate(bits):
        packed[i // 8] |= bit.as_unsigned() << (i % 8)
    return bytes(packed)
