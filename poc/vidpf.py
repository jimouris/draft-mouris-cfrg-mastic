"""Verifiable Distributed Point Function (VIDPF)"""

import itertools
from random import randrange
from typing import Generic, Self, TypeAlias, TypeVar

from vdaf_poc.common import to_le_bytes, vec_add, vec_neg, vec_sub, xor
from vdaf_poc.field import NttField
from vdaf_poc.idpf_bbcggi21 import pack_bits
from vdaf_poc.xof import XofFixedKeyAes128, XofTurboShake128

from dst import USAGE_CONVERT, USAGE_EXTEND, USAGE_NODE_PROOF, dst

F = TypeVar("F", bound=NttField)

PROOF_SIZE: int = 32

Ctrl: TypeAlias = list[bool]

CorrectionWord: TypeAlias = tuple[
    bytes,    # seed
    Ctrl,     # control bits
    list[F],  # payload
    bytes,    # node proof
]


class PrefixTreeIndex:
    def __init__(self, path: tuple[bool, ...]):
        self.path = path

    def encode(self) -> bytes:
        encoded = bytearray()
        for chunk in itertools.batched(self.path, 8):
            byte_out = 0
            for (bit_position, bit) in enumerate(chunk):
                byte_out |= bit << (7 - bit_position)
            encoded.append(byte_out)
        return encoded

    def level(self) -> int:
        return len(self.path) - 1

    def sibling(self) -> Self:
        return self.__class__(self.path[:-1] + (not self.path[-1],))

    def left_sibling(self) -> Self:
        return self.__class__(self.path[:-1] + (False,))

    def right_sibling(self) -> Self:
        return self.__class__(self.path[:-1] + (True,))

    def __hash__(self):
        return hash(self.path)

    def __eq__(self, other):
        return self.path == other.path


class PrefixTreeEntry(Generic[F]):
    seed: bytes   # selected seed
    ctrl: bool    # selected control bit
    w: list[F]    # weight
    proof: bytes  # node proof

    def __init__(self,
                 seed: bytes,
                 ctrl: bool,
                 w: list[F],
                 proof: bytes):
        self.seed = seed
        self.ctrl = ctrl
        self.w = w
        self.proof = proof
        self.left_child = None
        self.right_child = None

    @classmethod
    def root(cls, seed: bytes, ctrl: bool):
        # The weight and node proof won't be used.
        return cls(seed, ctrl, [], bytes())


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
            alpha: tuple[bool, ...],
            beta: list[F],
            ctx: bytes,
            nonce: bytes,
            rand: bytes,
            ) -> tuple[list[CorrectionWord], list[bytes]]:
        '''
        The VIDPF key generation algorithm.

        Returns the public share (i.e., the correction word for each
        level of the tree) and two keys, one for each aggregator.

        Implementation note: for clarity, this algorithm has not been
        written in a manner that is side-channel resistant. To avoid
        leaking `alpha` via a side-channel, implementations should avoid
        branching or indexing into arrays in a data-dependent manner.
        '''
        if len(alpha) != self.BITS:
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
            idx = PrefixTreeIndex(alpha[:i+1])
            bit = alpha[i]

            # [MST24]: if x = 0 then keep <- L, lose <- R
            #
            # Implementation note: the value of `bit` is
            # `alpha`-dependent.
            (keep, lose) = (1, 0) if bit else (0, 1)

            # Extend: compute the left and right children the current
            # level of the tree. During evaluation, one of these children
            # will be selected as the next seed and control bit.
            #
            # [MST24]: s_0^L || s_0^R || t_0^L || t_0^R
            #          s_1^L || s_1^R || t_1^L || t_1^R
            (s0, t0) = self.extend(seed[0], ctx, nonce)
            (s1, t1) = self.extend(seed[1], ctx, nonce)

            # Compute the correction words for this level's seed and
            # control bit. Our goal is to maintain the following
            # invariant, after correction:
            #
            # * If evaluation is on path, then each aggregator will
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
            (seed[0], w0) = self.convert(s0[keep], ctx, nonce)
            (seed[1], w1) = self.convert(s1[keep], ctx, nonce)
            ctrl[0] = t0[keep]  # [MST24]: t0'
            ctrl[1] = t1[keep]  # [MST24]: t1'

            # Compute the correction word for this level's payload.
            #
            # Implementation note: `ctrl` is `alpha`-dependent.
            w_cw = vec_add(vec_sub(beta, w0), w1)
            if ctrl[1]:
                w_cw = vec_neg(w_cw)

            # Compute the correction word for this level's node proof. If
            # evaluation is on path, then exactly one of the aggregatos
            # will correct their node proof, causing them to compute the
            # same node value. If evaluation is off path, then both will
            # correct or neither will; and since they compute the same
            # seed, they will again compute the same value.
            proof_cw = xor(
                self.node_proof(seed[0], ctx, idx),
                self.node_proof(seed[1], ctx, idx),
            )

            correction_words.append((seed_cw, ctrl_cw, w_cw, proof_cw))

        return (correction_words, keys)

    def eval_with_siblings(self,
                           agg_id: int,
                           correction_words: list[CorrectionWord],
                           key: bytes,
                           level: int,
                           prefixes: tuple[tuple[bool, ...], ...],
                           ctx: bytes,
                           nonce: bytes,
                           ) -> tuple[list[list[F]], PrefixTreeEntry]:
        """
        The VIDPF key evaluation algorithm.

        The return value consists of the weights for each candidate prefix and
        the root of the prefix tree. The prefix tree includes the prefixes and
        the siblings of each node visited.
        """
        if agg_id not in range(2):
            raise ValueError("invalid aggregator ID")
        if len(correction_words) != self.BITS:
            raise ValueError("corrections words has incorrect length")
        if level not in range(self.BITS):
            raise ValueError("level too deep")
        for prefix in prefixes:
            if len(prefix) != level + 1:
                raise ValueError("prefix with incorrect length")
        if len(set(prefixes)) != len(prefixes):
            raise ValueError("candidate prefixes are non-unique")

        # Evaluate our share of the prefix tree, including the sibling of each
        # node we visit.
        #
        # Implementation note: we can save computation by storing the tree
        # across `eval()` calls for the same report.
        root = PrefixTreeEntry.root(key, bool(agg_id))
        out_share = []
        for prefix in prefixes:
            n = root
            for (i, bit) in enumerate(prefix):
                idx = PrefixTreeIndex(prefix[:i+1])
                if n.left_child is None:
                    n.left_child = self.eval_next(n, correction_words[i], ctx,
                                                  nonce, idx.left_sibling())
                if n.right_child is None:
                    n.right_child = self.eval_next(n, correction_words[i], ctx,
                                                   nonce, idx.right_sibling())
                n = n.right_child if bit else n.left_child
            out_share.append(n.w if agg_id == 0 else vec_neg(n.w))

        return (out_share, root)

    def get_beta_share(
            self,
            agg_id: int,
            correction_words: list[CorrectionWord],
            key: bytes,
            ctx: bytes,
            nonce: bytes,
    ) -> list[F]:
        root = PrefixTreeEntry.root(key, bool(agg_id))
        left = self.eval_next(root, correction_words[0], ctx, nonce,
                              PrefixTreeIndex((False,)))
        right = self.eval_next(root, correction_words[0], ctx, nonce,
                               PrefixTreeIndex((True,)))
        beta_share = vec_add(left.w, right.w)
        if agg_id == 1:
            beta_share = vec_neg(beta_share)
        return beta_share

    def eval_next(self,
                  node: PrefixTreeEntry,
                  correction_word: CorrectionWord,
                  ctx: bytes,
                  nonce: bytes,
                  idx: PrefixTreeIndex,
                  ) -> PrefixTreeEntry:
        """
        Extend a node in the tree, select and correct one of its
        children, then convert it into a payload and the next seed.
        """
        (seed_cw, ctrl_cw, w_cw, proof_cw) = correction_word
        keep = int(idx.path[-1])

        # Extend.
        #
        # [MST24, Fig. 17]: (s^L, s^R), (t^L, t^R) = PRG(s^{i-1})
        (s, t) = self.extend(node.seed, ctx, nonce)

        # Correct.
        #
        # Implementation note: avoid branching on the value of control
        # bits, as its value may be leaked by a side channel.
        if node.ctrl:
            s[keep] = xor(s[keep], seed_cw)
            t[keep] ^= ctrl_cw[keep]

        # Convert and correct the payload.
        #
        # Implementation note: the conditional addition should be
        # replaced with a constant-time select in practice in order to
        # reduce leakage via timing side channels.
        (next_seed, w) = self.convert(s[keep], ctx, nonce)
        next_ctrl = t[keep]  # [MST24]: s^i, W^i, t'^i
        if next_ctrl:
            w = vec_add(w, w_cw)

        # Compute and correct the node proof.
        #
        # Implementation note: avoid branching on the control bit here.
        node_proof = self.node_proof(next_seed, ctx, idx)
        if next_ctrl:
            node_proof = xor(node_proof, proof_cw)

        return PrefixTreeEntry(next_seed, next_ctrl, w, node_proof)

    def verify(self, proof0: bytes, proof1: bytes) -> bool:
        return proof0 == proof1

    def extend(self,
               seed: bytes,
               ctx: bytes,
               nonce: bytes,
               ) -> tuple[list[bytes], Ctrl]:
        '''
        Extend a seed into the seed and control bits for its left and
        right children in the VIDPF tree.
        '''
        xof = XofFixedKeyAes128(seed, dst(ctx, USAGE_EXTEND), nonce)
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
                ctx: bytes,
                nonce: bytes,
                ) -> tuple[bytes, list[F]]:
        '''
        Convert a selected seed into a payload and the seed for the next
        level.
        '''
        xof = XofFixedKeyAes128(seed, dst(ctx, USAGE_CONVERT), nonce)
        next_seed = xof.next(XofFixedKeyAes128.SEED_SIZE)
        payload = xof.next_vec(self.field, self.VALUE_LEN)
        return (next_seed, payload)

    def node_proof(self,
                   seed: bytes,
                   ctx: bytes,
                   idx: PrefixTreeIndex) -> bytes:
        '''
        Compute the proof for this node.
        '''
        binder = \
            to_le_bytes(self.BITS, 2) + \
            to_le_bytes(idx.level(), 2) + \
            idx.encode()
        xof = XofTurboShake128(seed,
                               dst(ctx, USAGE_NODE_PROOF),
                               binder)
        return xof.next(PROOF_SIZE)

    def encode_public_share(
            self,
            public_share: list[CorrectionWord]) -> bytes:
        (seeds, ctrl, payloads, proofs) = zip(*public_share)
        encoded = bytes()
        encoded += pack_bits(list(itertools.chain.from_iterable(ctrl)))
        for seed in seeds:
            encoded += seed
        for payload in payloads:
            encoded += self.field.encode_vec(payload)
        for proof in proofs:
            encoded += proof
        return encoded

    def is_prefix(self,
                  x: tuple[bool, ...],
                  y: tuple[bool, ...],
                  level: int) -> bool:
        """
        Returns `True` iff `x` is the prefix of `y` at level `level`.

        Pre-conditions:

            - `level` in `range(self.BITS)`
        """
        return x == y[:level+1]

    def test_input_rand(self) -> tuple[bool, ...]:
        bits = []
        for _ in range(self.BITS):
            bits.append(bool(randrange(2)))
        return tuple(bits)

    def test_input_zero(self) -> tuple[bool, ...]:
        return tuple([False] * self.BITS)

    def test_index_from_int(self, value: int, length: int) -> tuple[bool, ...]:
        assert length <= self.BITS
        return tuple(
            (value >> (length - 1 - i)) & 1 != 0 for i in range(length)
        )

    def prefixes_for_level(self, level: int) -> tuple[tuple[bool, ...], ...]:
        return tuple(
            self.test_index_from_int(value, level+1) for value in range(2**level)
        )

    def test_eval(self,
                  agg_id: int,
                  correction_words: list[CorrectionWord],
                  key: bytes,
                  level: int,
                  prefixes: tuple[tuple[bool, ...], ...],
                  ctx: bytes,
                  nonce: bytes,
                  ) -> tuple[list[list[F]], bytes]:
        """
        Evaluate the VIDPF on the given prefixes and compute the hash of the
        node proofs.

        This functionality is not used by Mastic. It is intended for testing
        VIDPF.
        """
        import hashlib

        (out_share, root) = self.eval_with_siblings(
            agg_id,
            correction_words,
            key,
            level,
            prefixes,
            ctx,
            nonce,
        )

        h = hashlib.sha3_256()
        q: list[PrefixTreeEntry] = []
        if root.left_child is not None:
            q.append(root.left_child)
        if root.right_child is not None:
            q.append(root.right_child)
        while len(q) > 0:
            (n, q) = (q[0], q[1:])
            h.update(n.proof)
            if n.left_child is not None:
                q.append(n.left_child)
            if n.right_child is not None:
                q.append(n.right_child)
        return (out_share, h.digest())
