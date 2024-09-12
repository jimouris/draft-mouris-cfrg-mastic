"""Verifiable Distributed Point Function (VIDPF)"""

import itertools
from typing import Generic, Self, Sequence, TypeAlias, TypeVar

from vdaf_poc.common import (format_dst, to_le_bytes, vec_add, vec_neg,
                             vec_sub, xor, zeros)
from vdaf_poc.field import Field2, NttField
from vdaf_poc.xof import XofFixedKeyAes128, XofTurboShake128

F = TypeVar("F", bound=NttField)

PROOF_SIZE = 32

# Walk proof for an empty tree.
PROOF_INIT = XofTurboShake128(zeros(XofTurboShake128.SEED_SIZE),
                              b"vidpf proof init",
                              b'').next(PROOF_SIZE)

# TODO Consider using `bool` instead of `Field2` to improve readability.
Ctrl: TypeAlias = list[Field2]

CorrectionWord: TypeAlias = tuple[
    bytes,    # seed
    Ctrl,     # control bits
    list[F],  # payload
    bytes,    # node proof
]


class PrefixTreeIndex:
    node: int
    level: int

    def __init__(self, node: int, level: int):
        self.node = node
        self.level = level

    def sibling(self) -> Self:
        return self.__class__(self.node ^ 1, self.level)

    def left_child(self) -> Self:
        return self.__class__(self.node << 1, self.level+1)

    def right_child(self) -> Self:
        return self.left_child().sibling()

    def __hash__(self):
        return hash((self.node, self.level))

    def __eq__(self, other):
        return self.node == other.node and self.level == other.level


class PrefixTreeEntry(Generic[F]):
    seed: bytes   # selected seed
    ctrl: Field2  # selected control bit
    w: list[F]    # payload
    proof: bytes  # proof for this walk so far

    def __init__(self,
                 seed: bytes,
                 ctrl: Field2,
                 w: list[F],
                 proof: bytes):
        self.seed = seed
        self.ctrl = ctrl
        self.w = w
        self.proof = proof


class Vidpf(Generic[F]):
    """
    The Verifiable Incremental Distributed Point Function (VIDPF) of [MST24].
    """

    # Size in bytes of each VIDPF key.
    KEY_SIZE = XofFixedKeyAes128.SEED_SIZE

    # Size in bytes of the nonce.
    NONCE_SIZE = XofFixedKeyAes128.SEED_SIZE

    # Number of random bytes consumed by the VIDPF key generation algorithm.
    RAND_SIZE = 2 * XofFixedKeyAes128.SEED_SIZE

    def __init__(self, field: type[F], bits: int, value_len: int):
        self.field = field
        self.BITS = bits
        self.VALUE_LEN = value_len

    def gen(self,
            alpha: int,
            beta: list[F],
            nonce: bytes,
            rand: bytes,
            ) -> tuple[list[CorrectionWord], list[bytes]]:
        '''
        The VIDPF key generation algorithm.

        Returns the public share (i.e., the correction word for each
        level of the tree) and two keys, one fore each aggregator.

        Implementation note: for clarity, this algorithm has not been
        written in a manner that is side-channel resistant. To avoid
        leading `alpha` via a side-channel, implementations should avoid
        branching or indexing into arrays in a data-dependent manner.
        '''
        if alpha not in range(2 ** self.BITS):
            raise ValueError("alpha out of range")
        if len(beta) != self.VALUE_LEN:
            raise ValueError("incorrect beta length")
        if len(nonce) != self.NONCE_SIZE:
            raise ValueError("incorrect nonce size")
        if len(rand) != self.RAND_SIZE:
            raise ValueError("randomness has incorrect length")

        keys = [rand[:self.KEY_SIZE], rand[self.KEY_SIZE:]]

        # [MST24, Fig. 15]: s0^0, s1^0, t0^0, t1^0
        seed = keys.copy()
        ctrl = [Field2(0), Field2(1)]
        correction_words = []
        for i in range(self.BITS):
            node = (alpha >> (self.BITS - i - 1))
            bit = node & 1

            # [MST24]: if x = 0 then keep <- L, lose <- R
            #
            # Implementation note: the value of `bits` is
            # `alpha`-dependent.
            (keep, lose) = (1, 0) if bit else (0, 1)

            # Extend: compute the left and right children the current
            # level of the tree. During evaluation, one of these children
            # will be selected as the next seed and control bit.
            #
            # [MST24]: s_0^L || s_0^R || t_0^L || t_0^R
            #          s_1^L || s_1^R || t_1^L || t_1^R
            (s0, t0) = self.extend(seed[0], nonce)
            (s1, t1) = self.extend(seed[1], nonce)

            # Compute the seed and control bit of this level's correction
            # word. Our goal is to maintain the following invariant,
            # after correction:
            #
            # * If evaluation is on path, then the seed should be
            #   pseudorandom and the control bit should be `bit`. The
            #   seed is the sum of the shares of the seeds we're
            #  "losing" from the extended seed.
            #
            # * If evaluation is off path, then the seed should be the
            #   all zero string and the control should be `1-bit`.
            #
            # Implementation note: the index `lose` is `alpha`-dependent.
            seed_cw = xor(s0[lose], s1[lose])
            ctrl_cw = [
                t0[0] + t1[0] + Field2(1-bit),  # [MST24]: t_c^L
                t0[1] + t1[1] + Field2(bit),    # [MST24]: t_c^R
            ]

            # Correct.
            #
            # Implementation note: the index `keep` is `alpha`-dependent,
            # as is `ctrl`.
            if ctrl[0] == Field2(1):
                s0[keep] = xor(s0[keep], seed_cw)
                t0[keep] = t0[keep] + ctrl_cw[keep]
            if ctrl[1] == Field2(1):
                s1[keep] = xor(s1[keep], seed_cw)
                t1[keep] = t1[keep] + ctrl_cw[keep]

            # Convert.
            (seed[0], w0) = self.convert(s0[keep], nonce)
            (seed[1], w1) = self.convert(s1[keep], nonce)
            ctrl[0] = t0[keep]  # [MST24]: t0'
            ctrl[1] = t1[keep]  # [MST24]: t1'

            # Compute the payload of this level's correction word.
            #
            # Implementation note: `ctrl` is `alpha`-dependent.
            w_cw = vec_add(vec_sub([self.field(1)] + beta, w0), w1)
            if ctrl[1] == Field2(1):
                w_cw = vec_neg(w_cw)

            # Compute the proof for this level's correction word. This is
            # used to correct the node proof during evaluation.
            proof_cw = xor(
                self.node_proof(seed[0], node, i),
                self.node_proof(seed[1], node, i),
            )

            correction_words.append((seed_cw, ctrl_cw, w_cw, proof_cw))

        return (correction_words, keys)

    def eval(self,
             agg_id: int,
             public_share: list[CorrectionWord],
             key: bytes,
             level: int,
             prefixes: Sequence[int],
             nonce: bytes,
             ) -> tuple[list[F], list[list[F]], bytes]:
        """
        The VIDPF key evaluation algorithm.

        Return the aggregator's share of `beta`, its output share for
        each prefix, and its proof.
        """
        if agg_id not in range(2):
            raise ValueError("invalid aggregator ID")
        if len(public_share) != self.BITS:
            raise ValueError("corrections words list has incorrect length")
        if level not in range(self.BITS):
            raise ValueError("level too deep")
        if len(set(prefixes)) != len(prefixes):
            raise ValueError("candidate prefixes are non-unique")

        # Evaluate our share of the prefix tree. Along the way, compute
        # the walk proof. (TODO Define "walk proof" and probably call it
        # something else.)
        #
        # Implementation note: we can save computation by storing
        # `prefix_tree_share` across `eval()` calls for the same report.
        prefix_tree_share: dict[PrefixTreeIndex, PrefixTreeEntry] = {}
        proof = PROOF_INIT
        for prefix in prefixes:
            if prefix not in range(2 ** (level+1)):
                raise ValueError("prefix too long")

            seed = key
            ctrl = Field2(agg_id)
            for i in range(level+1):
                node = prefix >> (level - i)
                idx = PrefixTreeIndex(node, i)
                for inner_idx in [idx, idx.sibling()]:
                    # Compute the value for the node and its sibling. The
                    # sibling is used to compute the path and counter for the
                    # evaluation proof.
                    if not prefix_tree_share.get(inner_idx):
                        prefix_tree_share[inner_idx] = self.eval_next(
                            seed,
                            ctrl,
                            public_share[i],
                            i,
                            inner_idx.node,
                            proof,
                            nonce,
                        )
                entry = prefix_tree_share[idx]
                seed = entry.seed
                ctrl = entry.ctrl
                proof = entry.proof

        # Compute the aggregator's share of `beta`.
        w0 = prefix_tree_share[PrefixTreeIndex(0, 0)].w
        w1 = prefix_tree_share[PrefixTreeIndex(1, 0)].w
        beta_share = vec_add(w0, w1)[1:]
        if agg_id == 1:
            beta_share = vec_neg(beta_share)

        # Check that the first element of the payload is equal to 1.
        #
        # Each aggregator holds an additive share of the counter, so we
        # aggregator 1 negate its share and add 1 so that they both
        # compute the same value for `counter`.
        counter = self.field.encode_vec([w0[0] + w1[0] + self.field(agg_id)])

        # Path check: For each node, check that the payload is equal to
        # the sum of its children.
        path = b''
        for prefix in prefixes:
            for i in range(level):
                node = prefix >> (level - i)
                idx = PrefixTreeIndex(node, i)
                w = prefix_tree_share[idx].w
                w0 = prefix_tree_share[idx.left_child()].w
                w1 = prefix_tree_share[idx.right_child()].w
                path += self.field.encode_vec(vec_sub(w, vec_add(w0, w1)))

        # Compute the aggregator's output share.
        out_share = []
        for prefix in prefixes:
            w = prefix_tree_share[PrefixTreeIndex(prefix, level)].w
            out_share.append(w if agg_id == 0 else vec_neg(w))

        # Compute the evaluation proof. If both aggregators compute the
        # same value, then they agree on the walk proof, path and
        # counter.
        proof = eval_proof(proof, counter, path)
        return (beta_share, out_share, proof)

    def eval_next(self,
                  seed: bytes,
                  ctrl: Field2,
                  correction_word: CorrectionWord,
                  i: int,  # current level
                  node: int,
                  proof: bytes,
                  nonce: bytes,
                  ) -> PrefixTreeEntry:
        """
        Extend a node in the tree, select and correct one of its
        children, then convert it into a payload and the next seed.
        """
        (seed_cw, ctrl_cw, w_cw, proof_cw) = correction_word
        keep = node & 1

        # Extend.
        #
        # [MST24, Fig. 17]: (s^L, s^R), (t^L, t^R) = PRG(s^{i-1})
        (s, t) = self.extend(seed, nonce)

        # Correct.
        #
        # Implementation note: avoid branching on the value of control bits, as
        # its value may be leaked by a side channel.
        if ctrl == Field2(1):
            s[keep] = xor(s[keep], seed_cw)
            t[keep] = t[keep] + ctrl_cw[keep]

        # Convert and correct the payload.
        #
        # Implementation note: the conditional addition should be
        # replaced with a constant-time select in practice in order to
        # reduce leakage via timing side channels.
        (next_seed, w) = self.convert(s[keep], nonce)  # [MST24]: s^i, W^i
        next_ctrl = t[keep]  # [MST24]: t'^i
        if next_ctrl == Field2(1):
            w = vec_add(w, w_cw)

        # [MST24]: pi' = H(x^{<= i} || s^i)
        pi_prime = self.node_proof(next_seed, node, i)

        # \pi = \pi xor H(\pi \xor (proof_prime \xor next_ctrl * proof_cw))
        #
        # Implementation note: avoid branching on the control bit here.
        if next_ctrl == Field2(1):
            h2 = xor(proof, xor(pi_prime, proof_cw))
        else:
            h2 = xor(proof, pi_prime)
        proof = xor(proof, pi_proof_adjustment(h2))

        return PrefixTreeEntry(next_seed, next_ctrl, w, proof)

    def verify(self, proof0: bytes, proof1: bytes) -> bool:
        return proof0 == proof1

    def extend(self,
               seed: bytes,
               nonce: bytes,
               ) -> tuple[list[bytes], Ctrl]:
        '''
        Extend a seed into the seed and control bits for its left and
        right children in the VIDPF tree.
        '''
        xof = XofFixedKeyAes128(seed, format_dst(1, 0, 0), nonce)
        s = [
            bytearray(xof.next(self.KEY_SIZE)),
            bytearray(xof.next(self.KEY_SIZE)),
        ]
        # Use the least significant bits as the control bit correction,
        # and then zero it out. This gives effectively 127 bits of
        # security, but reduces the number of AES calls needed by 1/3.
        t = [Field2(s[0][0] & 1), Field2(s[1][0] & 1)]
        s[0][0] &= 0xFE
        s[1][0] &= 0xFE
        return ([bytes(s[0]), bytes(s[1])], t)

    def convert(self,
                seed: bytes,
                nonce: bytes,
                ) -> tuple[bytes, list[F]]:
        '''
        Convert a selected seed into a payload and the seed for the next
        level.
        '''
        xof = XofFixedKeyAes128(seed, format_dst(1, 0, 1), nonce)
        next_seed = xof.next(XofFixedKeyAes128.SEED_SIZE)
        payload = xof.next_vec(self.field, 1+self.VALUE_LEN)
        return (next_seed, payload)

    def node_proof(self,
                   seed: bytes,
                   node: int,
                   level: int,
                   ) -> bytes:
        '''
        Compute the proof for this node.
        '''
        binder = \
            to_le_bytes(self.BITS, 2) + \
            to_le_bytes(node, (self.BITS + 7) // 8) + \
            to_le_bytes(level, 2)
        xof = XofTurboShake128(seed, b'vidpf proof step', binder)
        return xof.next(PROOF_SIZE)

    def encode_public_share(self, correction_words: list[CorrectionWord]):
        # TODO(cjpatton) Align with Poplar1 public share in draft-irtf-cfrg-vdaf-12
        encoded = bytes()
        control_bits = list(itertools.chain.from_iterable(
            cw[1] for cw in correction_words
        ))
        encoded += pack_bits(control_bits)
        for (seed_cw, _ctrl_cw, w_cw, proof_cw) in correction_words:
            encoded += seed_cw
            encoded += self.field.encode_vec(w_cw)
            encoded += proof_cw
        return encoded


def pi_proof_adjustment(h2):
    xof = XofTurboShake128(
        zeros(XofTurboShake128.SEED_SIZE),
        b'vidpf proof adjustment',
        h2,
    )
    return xof.next(PROOF_SIZE)


def eval_proof(proof: bytes, counter: bytes, path: bytes) -> bytes:
    xof = XofTurboShake128(
        zeros(XofTurboShake128.SEED_SIZE),
        b'vidpf eval proof',
        proof + counter + path,
    )
    return xof.next(PROOF_SIZE)


def pack_bits(bits):
    byte_len = (len(bits) + 7) // 8
    packed = [int(0)] * byte_len
    for i, bit in enumerate(bits):
        packed[i // 8] |= bit.as_unsigned() << (i % 8)
    return bytes(packed)
