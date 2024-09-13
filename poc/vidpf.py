"""Verifiable Distributed Point Function (VIDPF)"""

import itertools
from typing import Generic, Self, Sequence, TypeAlias, TypeVar

from vdaf_poc.common import (format_dst, to_le_bytes, vec_add, vec_neg,
                             vec_sub, xor, zeros)
from vdaf_poc.field import NttField
from vdaf_poc.idpf_bbcggi21 import pack_bits
from vdaf_poc.xof import XofFixedKeyAes128, XofTurboShake128

F = TypeVar("F", bound=NttField)

PROOF_SIZE = 32

# Walk proof for an empty tree.
PATH_PROOF_INIT = XofTurboShake128(zeros(XofTurboShake128.SEED_SIZE),
                                   b"vidpf path proof init",
                                   b'').next(PROOF_SIZE)

Ctrl: TypeAlias = list[bool]

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
    seed: bytes  # selected seed
    ctrl: bool   # selected control bit
    w: list[F]   # payload

    def __init__(self,
                 seed: bytes,
                 ctrl: bool,
                 w: list[F]):
        self.seed = seed
        self.ctrl = ctrl
        self.w = w

    @classmethod
    def root(cls, seed: bytes, ctrl: bool):
        # The payload won't be used, so don't bother setting it.
        return cls(seed, ctrl, [])


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
        ctrl = [False, True]
        correction_words = []
        for i in range(self.BITS):
            idx = PrefixTreeIndex(alpha >> (self.BITS - i - 1), i)
            bit = bool(idx.node & 1)

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

            # Compute the correction words for this level's seed and
            # control bit. Our goal is to maintain the following
            # invariant, after correction:
            #
            # * If evaluation is on path, then each aggregator's will
            #   compute a different seed and their control bits will be
            #   secret shares of one.
            #
            # * If evaluation is off path, then the aggregators will
            #   compute the same seed and their control bits will be
            #   shares of zero.
            #
            # Implementation note: the index `lose` is `alpha`-dependent.
            seed_cw = xor(s0[lose], s1[lose])
            ctrl_cw = [
                t0[0] ^ t1[0] ^ (not bit),  # [MST24]: t_c^L
                t0[1] ^ t1[1] ^ bit,        # [MST24]: t_c^R
            ]

            # Correct.
            #
            # Implementation note: the index `keep` is `alpha`-dependent,
            # as is `ctrl`.
            if ctrl[0]:
                s0[keep] = xor(s0[keep], seed_cw)
                t0[keep] ^= ctrl_cw[keep]
            if ctrl[1]:
                s1[keep] = xor(s1[keep], seed_cw)
                t1[keep] ^= ctrl_cw[keep]

            # Convert.
            (seed[0], w0) = self.convert(s0[keep], nonce)
            (seed[1], w1) = self.convert(s1[keep], nonce)
            ctrl[0] = t0[keep]  # [MST24]: t0'
            ctrl[1] = t1[keep]  # [MST24]: t1'

            # Compute the correction word for this level's payload.
            #
            # Implementation note: `ctrl` is `alpha`-dependent.
            w_cw = vec_add(vec_sub([self.field(1)] + beta, w0), w1)
            if ctrl[1]:
                w_cw = vec_neg(w_cw)

            # Compute the correction word for this level's node proof. If
            # evaluation is on path, then exactly one of the aggregatos
            # will correct their node proof, causing them to compute the
            # same node value. If evaluation is off path, then both will
            # correct or neither will; and since they compute the same
            # seed, they will again compute the same value.
            proof_cw = xor(
                self.node_proof(seed[0], idx),
                self.node_proof(seed[1], idx),
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
        each prefix, and its evaluation proof.
        """
        if agg_id not in range(2):
            raise ValueError("invalid aggregator ID")
        if len(public_share) != self.BITS:
            raise ValueError("corrections words list has incorrect length")
        if level not in range(self.BITS):
            raise ValueError("level too deep")
        if len(set(prefixes)) != len(prefixes):
            raise ValueError("candidate prefixes are non-unique")

        # Evaluate our share of the prefix tree and compute the path proof.
        #
        # Implementation note: we can save computation by storing
        # `prefix_tree_share` across `eval()` calls for the same report.
        prefix_tree_share: dict[PrefixTreeIndex, PrefixTreeEntry] = {}
        root = PrefixTreeEntry.root(key, bool(agg_id))
        path_proof = PATH_PROOF_INIT
        for i in range(level+1):
            for prefix in prefixes:
                if prefix not in range(2 ** (level+1)):
                    raise ValueError("prefix too long")

                # Compute the entry for `prefix`. To do so, we first need to
                # look up the parent node.
                #
                # The index of the current prefix `prefix` is
                # `PrefixTreeIndex(prefix >> (level - i), i)`. Its parent
                # is at level `i - 1`.
                idx = PrefixTreeIndex(prefix >> (level - i + 1), i - 1)
                node = prefix_tree_share.setdefault(idx, root)
                for child_idx in [idx.left_child(), idx.right_child()]:
                    # Compute the entry for `prefix` and its sibling. The
                    # sibling is used for the counter and payload checks.
                    if not prefix_tree_share.get(child_idx):
                        (child, path_proof) = self.eval_next(
                            node,
                            path_proof,
                            public_share[i],
                            nonce,
                            child_idx,
                        )
                        prefix_tree_share[child_idx] = child

        # Compute the aggregator's share of `beta`.
        w0 = prefix_tree_share[PrefixTreeIndex(0, 0)].w
        w1 = prefix_tree_share[PrefixTreeIndex(1, 0)].w
        beta_share = vec_add(w0, w1)[1:]
        if agg_id == 1:
            beta_share = vec_neg(beta_share)

        # Counter check: check that the first element of the payload is equal
        # to 1.
        #
        # Each aggregator holds an additive share of the counter, so we
        # aggregator 1 negate its share and add 1 so that they both
        # compute the same value for `counter`.
        counter_check = self.field.encode_vec(
            [w0[0] + w1[0] + self.field(agg_id)])

        # Payload check: for each node, check that the payload is equal to
        # the sum of its children.
        payload_check = b''
        for prefix in prefixes:
            for i in range(level):
                idx = PrefixTreeIndex(prefix >> (level - i), i)
                w = prefix_tree_share[idx].w
                w0 = prefix_tree_share[idx.left_child()].w
                w1 = prefix_tree_share[idx.right_child()].w
                payload_check += self.field.encode_vec(
                    vec_sub(w, vec_add(w0, w1)))

        # Compute the aggregator's output share.
        out_share = []
        for prefix in prefixes:
            idx = PrefixTreeIndex(prefix, level)
            w = prefix_tree_share[idx].w
            out_share.append(w if agg_id == 0 else vec_neg(w))

        # Compute the evaluation proof. If both aggregators compute the same
        # value, then they agree on the path proof, the counter, and the
        # payload.
        proof = eval_proof(path_proof, counter_check, payload_check)
        return (beta_share, out_share, proof)

    def eval_next(self,
                  node: PrefixTreeEntry,
                  path_proof: bytes,
                  correction_word: CorrectionWord,
                  nonce: bytes,
                  idx: PrefixTreeIndex,
                  ) -> tuple[PrefixTreeEntry, bytes]:
        """
        Extend a node in the tree, select and correct one of its
        children, then convert it into a payload and the next seed.
        """
        (seed_cw, ctrl_cw, w_cw, proof_cw) = correction_word
        keep = idx.node & 1

        # Extend.
        #
        # [MST24, Fig. 17]: (s^L, s^R), (t^L, t^R) = PRG(s^{i-1})
        (s, t) = self.extend(node.seed, nonce)

        # Correct.
        #
        # Implementation note: avoid branching on the value of control bits, as
        # its value may be leaked by a side channel.
        if node.ctrl:
            s[keep] = xor(s[keep], seed_cw)
            t[keep] ^= ctrl_cw[keep]

        # Convert and correct the payload.
        #
        # Implementation note: the conditional addition should be
        # replaced with a constant-time select in practice in order to
        # reduce leakage via timing side channels.
        (next_seed, w) = self.convert(s[keep], nonce)  # [MST24]: s^i, W^i
        next_ctrl = t[keep]  # [MST24]: t'^i
        if next_ctrl:
            w = vec_add(w, w_cw)

        # Compute and correct the node proof and update the path proof.
        #
        # [MST24]: \tilde\pi = H_1(x^{\leq i} || s^\i)
        #          \pi = \tilde \pi \xor
        #             H_2(\pi \xor (\tilde\pi \xor t^\i \cdot \cs^\i)
        #
        # Implementation note: avoid branching on the control bit here.
        node_proof = self.node_proof(next_seed, idx)
        if next_ctrl:
            node_proof = xor(node_proof, proof_cw)
        path_proof = xor(path_proof,
                         adjusted_proof(xor(path_proof, node_proof)))

        return (PrefixTreeEntry(next_seed, next_ctrl, w), path_proof)

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
        t = [bool(s[0][0] & 1), bool(s[1][0] & 1)]
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
                   idx: PrefixTreeIndex) -> bytes:
        '''
        Compute the proof for this node.
        '''
        binder = \
            to_le_bytes(self.BITS, 2) + \
            to_le_bytes(idx.node, (self.BITS + 7) // 8) + \
            to_le_bytes(idx.level, 2)
        xof = XofTurboShake128(seed, b'vidpf path proof step', binder)
        return xof.next(PROOF_SIZE)

    def encode_public_share(
            self,
            public_share: list[CorrectionWord]) -> bytes:
        from vdaf_poc.field import Field2
        (seeds, ctrl, payloads, proofs) = zip(*public_share)
        encoded = bytes()
        encoded += pack_bits(list(
            # `pack_bits()` expects a `list[Field2]`, so we need to
            # convert from `bool` to `Field2` here.
            map(lambda bit: Field2(int(bit)),
                itertools.chain.from_iterable(ctrl))))
        for seed in seeds:
            encoded += seed
        for payload in payloads:
            encoded += self.field.encode_vec(payload)
        for proof in proofs:
            encoded += proof
        return encoded

    def is_prefix(self, x: int, y: int, level: int) -> bool:
        """
        Returns `True` iff `x` is the prefix of `y` at level `level`.

        Pre-conditions:

            - `level` in `range(self.BITS)`
        """
        return y >> (self.BITS - 1 - level) == x


def adjusted_proof(proof: bytes) -> bytes:
    xof = XofTurboShake128(proof, b'vidpf path proof adjustment', b'')
    return xof.next(PROOF_SIZE)


def eval_proof(path_proof: bytes,
               counter_check: bytes,
               payload_check: bytes) -> bytes:
    binder = counter_check + payload_check
    xof = XofTurboShake128(path_proof, b'vidpf eval proof', binder)
    return xof.next(PROOF_SIZE)
