'''The Mastic VDAF'''

import itertools
from typing import Any, Generic, Optional, TypeAlias, TypeVar, cast

from vdaf_poc.common import (concat, front, to_be_bytes, to_le_bytes, vec_add,
                             vec_neg, vec_sub)
from vdaf_poc.field import Field64, Field128, NttField
from vdaf_poc.flp_bbcggi19 import (Count, FlpBBCGGI19, Histogram,
                                   MultihotCountVec, Sum, SumVec, Valid)
from vdaf_poc.vdaf import Vdaf
from vdaf_poc.xof import XofTurboShake128

from dst import (USAGE_EVAL_PROOF, USAGE_JOINT_RAND, USAGE_JOINT_RAND_PART,
                 USAGE_JOINT_RAND_SEED, USAGE_ONEHOT_CHECK,
                 USAGE_PAYLOAD_CHECK, USAGE_PROOF_SHARE, USAGE_PROVE_RAND,
                 USAGE_QUERY_RAND, USAGE_WEIGHT_SHARE, dst_alg)
from vidpf import PROOF_SIZE, CorrectionWord, Vidpf

W = TypeVar("W")
R = TypeVar("R")
F = TypeVar("F", bound=NttField)


MasticAggParam: TypeAlias = tuple[
    int,                           # level
    tuple[tuple[bool, ...], ...],  # prefixes
    bool,                          # whether to do the weight check
]


class MasticLeaderInputShare(Generic[F]):
    key: bytes                             # VIDPF key
    seed: Optional[bytes]                  # FLP seed
    peer_joint_rand_part: Optional[bytes]  # FLP joint rand
    weight_share: list[F]
    proof_share: list[F]

    def __init__(self,
                 key: bytes,
                 seed: Optional[bytes],
                 peer_joint_rand_part: Optional[bytes],
                 weight_share: list[F],
                 proof_share: list[F]):
        self.key = key
        self.seed = seed
        self.peer_joint_rand_part = peer_joint_rand_part
        self.weight_share = weight_share
        self.proof_share = proof_share


class MasticHelperInputShare:
    key: bytes                             # VIDPF key
    seed: bytes                            # FLP seed
    peer_joint_rand_part: Optional[bytes]  # FLP joint rand

    def __init__(self,
                 key: bytes,
                 seed: bytes,
                 peer_joint_rand_part: Optional[bytes]):
        self.key = key
        self.seed = seed
        self.peer_joint_rand_part = peer_joint_rand_part


MasticInputShare: TypeAlias = MasticLeaderInputShare | MasticHelperInputShare

MasticPrepState: TypeAlias = tuple[
    list[F],          # Truncated output share
    Optional[bytes],  # Predicted FLP joint rand seed
]

MasticPrepShare: TypeAlias = tuple[
    bytes,              # VIDPF proof
    Optional[list[F]],  # FLP verifier share
    Optional[bytes],    # FLP joint randomness part
]

MasticPrepMessage: TypeAlias = Optional[bytes]  # FLP joint rand seed


class Mastic(
        Vdaf[
            tuple[tuple[bool, ...], W],  # W
            MasticAggParam,
            list[CorrectionWord],  # PublicShare
            MasticInputShare,
            list[F],  # OutShare
            list[F],  # AggShare
            list[R],  # R
            MasticPrepState,
            MasticPrepShare,
            MasticPrepMessage,
        ]):

    # NOTE We'd like to make this generic, but this appears to be blocked
    # by a bug. We would add `Generic[W, R, X, F]` as
    # one of the super classes of `Mastic`, but this causes a runtime
    # error.
    xof = XofTurboShake128

    ID: int = 0xFFFFFFFF
    VERIFY_KEY_SIZE = XofTurboShake128.SEED_SIZE
    NONCE_SIZE = 16
    SHARES = 2
    ROUNDS = 1

    # Name of the VDAF, for use in test vector filenames.
    test_vec_name = 'Mastic'

    def __init__(self,
                 bits: int,
                 valid: Valid[W, R, F]):
        self.field = valid.field
        self.flp = FlpBBCGGI19(valid)
        self.vidpf = Vidpf(valid.field, bits, 1 + valid.OUTPUT_LEN)
        self.RAND_SIZE = self.vidpf.RAND_SIZE + 2 * self.xof.SEED_SIZE
        if self.flp.JOINT_RAND_LEN > 0:  # FLP leader seed
            self.RAND_SIZE += self.xof.SEED_SIZE

    def shard(self,
              ctx: bytes,
              measurement: tuple[tuple[bool, ...], W],
              nonce: bytes,
              rand: bytes,
              ) -> tuple[list[CorrectionWord], list[MasticInputShare]]:
        # Encode the inputs to VIDPF key generation. The output, denoted
        # `beta`, is a counter concatenated with the truncated, encoded weight.
        (alpha, weight) = measurement
        encoded_weight = self.flp.encode(weight)
        beta = [self.field(1)] + self.flp.truncate(encoded_weight)

        if self.flp.JOINT_RAND_LEN > 0:
            return self.shard_with_joint_rand(
                ctx, alpha, beta, encoded_weight, nonce, rand)
        return self.shard_without_joint_rand(
            ctx, alpha, beta, encoded_weight, nonce, rand)

    def shard_without_joint_rand(
            self,
            ctx: bytes,
            alpha: tuple[bool, ...],
            beta: list[F],
            encoded_weight: list[F],
            nonce: bytes,
            rand: bytes,
    ) -> tuple[list[CorrectionWord], list[MasticInputShare]]:
        (vidpf_rand, rand) = front(self.vidpf.RAND_SIZE, rand)
        (prove_rand_seed, rand) = front(self.xof.SEED_SIZE, rand)
        (helper_seed, rand) = front(self.xof.SEED_SIZE, rand)
        assert len(rand) == 0  # REMOVE ME

        # Generate VIDPF keys.
        (correction_words, keys) = \
            self.vidpf.gen(alpha, beta, ctx, nonce, vidpf_rand)

        # Split the encoded weight.
        helper_weight_share = self.helper_weight_share(ctx, helper_seed)
        leader_weight_share = vec_sub(encoded_weight, helper_weight_share)

        # Generate FLP and split it into shares.
        prove_rand = self.prove_rand(ctx, prove_rand_seed)
        proof = self.flp.prove(encoded_weight, prove_rand, [])
        helper_proof_share = self.helper_proof_share(ctx, helper_seed)
        leader_proof_share = vec_sub(proof, helper_proof_share)

        input_shares: list[MasticInputShare] = [
            MasticLeaderInputShare(keys[0], None, None, leader_weight_share,
                                   leader_proof_share),
            MasticHelperInputShare(keys[1], helper_seed, None),
        ]
        return (correction_words, input_shares)

    def shard_with_joint_rand(
            self,
            ctx: bytes,
            alpha: tuple[bool, ...],
            beta: list[F],
            encoded_weight: list[F],
            nonce: bytes,
            rand: bytes,
    ) -> tuple[list[CorrectionWord], list[MasticInputShare]]:
        (vidpf_rand, rand) = front(self.vidpf.RAND_SIZE, rand)
        (prove_rand_seed, rand) = front(self.xof.SEED_SIZE, rand)
        (helper_seed, rand) = front(self.xof.SEED_SIZE, rand)
        (leader_seed, rand) = front(self.xof.SEED_SIZE, rand)
        assert len(rand) == 0  # REMOVE ME

        # Generate VIDPF keys.
        (correction_words, keys) = \
            self.vidpf.gen(alpha, beta, ctx, nonce, vidpf_rand)

        # Split the encoded weight.
        helper_weight_share = self.helper_weight_share(ctx, helper_seed)
        leader_weight_share = vec_sub(encoded_weight, helper_weight_share)

        # Generate FLP joint randomness.
        joint_rand_parts = [
            self.joint_rand_part(ctx, leader_seed, leader_weight_share,
                                 nonce),
            self.joint_rand_part(ctx, helper_seed, helper_weight_share,
                                 nonce),
        ]
        joint_rand = self.joint_rand(
            ctx, self.joint_rand_seed(ctx, joint_rand_parts))

        # Generate FLP and split it into shares.
        prove_rand = self.prove_rand(ctx, prove_rand_seed)
        proof = self.flp.prove(encoded_weight, prove_rand, joint_rand)
        helper_proof_share = self.helper_proof_share(ctx, helper_seed)
        leader_proof_share = vec_sub(proof, helper_proof_share)

        leader_joint_rand_part: Optional[bytes] = joint_rand_parts[0]
        helper_joint_rand_part: Optional[bytes] = joint_rand_parts[1]
        input_shares: list[MasticInputShare] = [
            MasticLeaderInputShare(keys[0], leader_seed,
                                   helper_joint_rand_part, leader_weight_share,
                                   leader_proof_share),
            MasticHelperInputShare(keys[1], helper_seed,
                                   leader_joint_rand_part),
        ]
        return (correction_words, input_shares)

    def is_valid(self,
                 agg_param: MasticAggParam,
                 previous_agg_params: list[MasticAggParam],
                 ) -> bool:
        (level, _prefixes, do_weight_check) = agg_param

        # Check that the weight check is done exactly once.
        weight_checked = \
            (do_weight_check and len(previous_agg_params) == 0) or \
            (not do_weight_check and
                any(agg_param[2] for agg_param in previous_agg_params))

        # Check that the level is strictly increasing.
        level_increased = len(previous_agg_params) == 0 or \
            level > previous_agg_params[-1][0]

        return weight_checked and level_increased

    def prep_init(
            self,
            verify_key: bytes,
            ctx: bytes,
            agg_id: int,
            agg_param: MasticAggParam,
            nonce: bytes,
            correction_words: list[CorrectionWord],
            input_share: MasticInputShare,
    ) -> tuple[MasticPrepState, MasticPrepShare]:
        (level, prefixes, do_weight_check) = agg_param
        (key, weight_share, proof_share, seed, peer_joint_rand_part) = \
            self.expand_input_share(ctx, input_share)

        # Evaluate the VIDPF.
        (out_shares, root) = self.vidpf.eval_with_siblings(
            agg_id,
            correction_words,
            key,
            level,
            prefixes,
            ctx,
            nonce,
        )

        # Query the FLP if applicable.
        joint_rand_part = None
        joint_rand_seed = None
        verifier_share = None
        if do_weight_check:
            query_rand = self.query_rand(verify_key, ctx, nonce, level)
            joint_rand = []
            if self.flp.JOINT_RAND_LEN > 0:
                assert seed is not None
                assert peer_joint_rand_part is not None
                joint_rand_part = self.joint_rand_part(ctx, seed,
                                                       weight_share, nonce)
                if agg_id == 0:
                    joint_rand_parts = [joint_rand_part, peer_joint_rand_part]
                else:
                    joint_rand_parts = [peer_joint_rand_part, joint_rand_part]
                joint_rand_seed = self.joint_rand_seed(ctx, joint_rand_parts)
                joint_rand = self.joint_rand(ctx, joint_rand_seed)
            verifier_share = self.flp.query(
                weight_share,
                proof_share,
                query_rand,
                joint_rand,
                2,
            )

        # Payload and onehot checks.
        payload_check_binder = b''
        onehot_check_binder = b''
        assert root.left_child is not None
        assert root.right_child is not None
        root.w = [self.field(agg_id)] + self.flp.truncate(weight_share)
        if agg_id == 1:
            root.w = vec_neg(root.w)
        q = [root]
        while len(q) > 0:
            (n, q) = (q[0], q[1:])

            if n.left_child is not None and n.right_child is not None:
                # Update payload check. The weight of each node should equal
                # the sum of its children.
                payload_check_binder += self.field.encode_vec(
                    vec_sub(n.w, vec_add(n.left_child.w, n.right_child.w)))
                q += [n.left_child, n.right_child]

            # Update the onehot check.
            onehot_check_binder += n.proof

        payload_check = self.xof(
            b'',
            dst_alg(ctx, USAGE_PAYLOAD_CHECK, self.ID),
            payload_check_binder,
        ).next(PROOF_SIZE)

        onehot_check = self.xof(
            b'',
            dst_alg(ctx, USAGE_ONEHOT_CHECK, self.ID),
            onehot_check_binder,
        ).next(PROOF_SIZE)

        # Counter check: the first element of beta should equal 1.
        #
        # Each aggregator holds an additive share of the counter, so
        # we have aggregator 1 negate its share and add 1 so that they
        # both compute the same value for `counter`.
        w0 = root.left_child.w
        w1 = root.right_child.w
        counter_check = self.field.encode_vec(
            [w0[0] + w1[0] + self.field(agg_id)])

        # Evaluation proof: if both aggregators compute the same
        # value, then they agree on the onehot proof, the counter, and
        # the payload.
        eval_proof = self.xof(
            verify_key,
            dst_alg(ctx, USAGE_EVAL_PROOF, self.ID),
            onehot_check + counter_check + payload_check,
        ).next(PROOF_SIZE)

        flattened_out_share = []
        for out_share in out_shares:
            flattened_out_share += out_share

        prep_state = (flattened_out_share, joint_rand_seed)
        prep_share = (eval_proof, verifier_share, joint_rand_part)
        return (prep_state, prep_share)

    def prep_shares_to_prep(
            self,
            ctx: bytes,
            agg_param: MasticAggParam,
            prep_shares: list[MasticPrepShare],
    ) -> MasticPrepMessage:
        (_level, _prefixes, do_weight_check) = agg_param

        if len(prep_shares) != 2:
            raise ValueError('unexpected number of prep shares')

        (eval_proof_0,
         verifier_share_0,
         joint_rand_part_0) = prep_shares[0]
        (eval_proof_1,
         verifier_share_1,
         joint_rand_part_1) = prep_shares[1]

        # Verify the VIDPF output.
        if eval_proof_0 != eval_proof_1:
            raise Exception('VIDPF verification failed')

        if not do_weight_check:
            return None
        if verifier_share_0 is None or verifier_share_1 is None:
            raise ValueError('expected FLP verifier shares')

        # Verify the FLP.
        verifier = vec_add(verifier_share_0, verifier_share_1)
        if not self.flp.decide(verifier):
            raise Exception('FLP verification failed')

        if self.flp.JOINT_RAND_LEN == 0:
            return None
        if joint_rand_part_0 is None or joint_rand_part_1 is None:
            raise ValueError('expected FLP joint randomness parts')

        # Confirm the FLP joint randomness was computed properly.
        prep_msg = self.joint_rand_seed(ctx, [
            joint_rand_part_0,
            joint_rand_part_1,
        ])
        return prep_msg

    def prep_next(self,
                  _ctx: bytes,
                  prep_state: MasticPrepState,
                  prep_msg: MasticPrepMessage,
                  ) -> list[F]:
        (truncated_out_share, joint_rand_seed) = prep_state
        if joint_rand_seed is not None:
            if prep_msg is None:
                raise ValueError('expected joint rand confirmation')

            if prep_msg != joint_rand_seed:
                raise Exception('joint rand confirmation failed')

        return truncated_out_share

    def agg_init(self, agg_param: MasticAggParam) -> list[F]:
        (_level, prefixes, _do_weight_check) = agg_param
        agg = self.field.zeros(len(prefixes)*(1+self.flp.OUTPUT_LEN))
        return agg

    def agg_update(self,
                   agg_param: MasticAggParam,
                   agg_share: list[F],
                   out_share: list[F]) -> list[F]:
        return vec_add(agg_share, out_share)

    def merge(self,
              agg_param: MasticAggParam,
              agg_shares: list[list[F]]) -> list[F]:
        (_level, prefixes, _do_weight_check) = agg_param
        agg = self.agg_init(agg_param)
        for agg_share in agg_shares:
            agg = vec_add(agg, agg_share)
        return cast(list[F], agg)

    def unshard(self,
                agg_param: MasticAggParam,
                agg_shares: list[list[F]],
                _num_measurements: int,
                ) -> list[R]:
        agg = self.merge(agg_param, agg_shares)

        agg_result = []
        while len(agg) > 0:
            (chunk, agg) = front(self.flp.OUTPUT_LEN + 1, agg)
            meas_count = chunk[0].int()
            agg_result.append(self.flp.decode(chunk[1:], meas_count))
        return agg_result

    def encode_agg_param(self, agg_param: MasticAggParam) -> bytes:
        (level, prefixes, do_weight_check) = agg_param
        if level not in range(2 ** 16):
            raise ValueError('level out of range')
        if len(prefixes) not in range(2 ** 32):
            raise ValueError('number of prefixes out of range')
        encoded = bytes()
        encoded += to_be_bytes(level, 2)
        encoded += to_be_bytes(len(prefixes), 4)
        prefixes_len = ((level + 1) + 7) // 8 * len(prefixes)
        encoded_prefixes = bytearray()
        for prefix in prefixes:
            for chunk in itertools.batched(prefix, 8):
                byte_out = 0
                for (bit_position, bit) in enumerate(chunk):
                    byte_out |= bit << (7 - bit_position)
                encoded_prefixes.append(byte_out)
        assert len(encoded_prefixes) == prefixes_len
        encoded += encoded_prefixes
        # NOTE: The do_weight_check is the only difference between
        # Mastic's and Poplar1's `encode_agg_param`.
        encoded += to_be_bytes(int(do_weight_check), 1)
        return encoded

    def expand_input_share(
            self,
            ctx: bytes,
            input_share: MasticInputShare,
    ) -> tuple[bytes, list[F], list[F], Optional[bytes], Optional[bytes]]:
        key = input_share.key
        seed = input_share.seed
        peer_joint_rand_part = input_share.peer_joint_rand_part
        if isinstance(input_share, MasticLeaderInputShare):
            weight_share = input_share.weight_share
            proof_share = input_share.proof_share
        elif isinstance(input_share, MasticHelperInputShare):
            assert seed is not None
            weight_share = self.helper_weight_share(ctx, seed)
            proof_share = self.helper_proof_share(ctx, seed)
        return (key, weight_share, proof_share, seed, peer_joint_rand_part)

    def helper_weight_share(self, ctx, seed: bytes) -> list[F]:
        return self.xof.expand_into_vec(
            self.field,
            seed,
            dst_alg(ctx, USAGE_WEIGHT_SHARE, self.ID),
            b'',
            self.flp.MEAS_LEN,
        )

    def helper_proof_share(self, ctx, seed: bytes) -> list[F]:
        return self.xof.expand_into_vec(
            self.field,
            seed,
            dst_alg(ctx, USAGE_PROOF_SHARE, self.ID),
            b'',
            self.flp.PROOF_LEN,
        )

    def prove_rand(self, ctx: bytes, seed: bytes) -> list[F]:
        return self.xof.expand_into_vec(
            self.field,
            seed,
            dst_alg(ctx, USAGE_PROVE_RAND, self.ID),
            b'',
            self.flp.PROVE_RAND_LEN,
        )

    def joint_rand_part(
            self,
            ctx: bytes,
            seed: bytes,
            weight_share: list[F],
            nonce: bytes,
    ) -> bytes:
        return self.xof.derive_seed(
            seed,
            dst_alg(ctx, USAGE_JOINT_RAND_PART, self.ID),
            nonce + self.field.encode_vec(weight_share),
        )

    def joint_rand_seed(self, ctx: bytes, parts: list[bytes]) -> bytes:
        return self.xof.derive_seed(
            b'',
            dst_alg(ctx, USAGE_JOINT_RAND_SEED, self.ID),
            concat(parts),
        )

    def joint_rand(self, ctx: bytes, seed: bytes) -> list[F]:
        return self.xof.expand_into_vec(
            self.field,
            seed,
            dst_alg(ctx, USAGE_JOINT_RAND, self.ID),
            b'',
            self.flp.JOINT_RAND_LEN,
        )

    def query_rand(self,
                   verify_key: bytes,
                   ctx: bytes,
                   nonce: bytes,
                   level: int) -> list[F]:
        return self.xof.expand_into_vec(
            self.field,
            verify_key,
            dst_alg(ctx, USAGE_QUERY_RAND, self.ID),
            nonce + to_le_bytes(level, 2),
            self.flp.QUERY_RAND_LEN,
        )

    def test_vec_set_type_param(self, test_vec: dict[str, Any]) -> list[str]:
        test_vec['vidpf_bits'] = int(self.vidpf.BITS)
        return ['vidpf_bits'] + self.flp.test_vec_set_type_param(test_vec)

    def test_vec_encode_input_share(
        self,
        input_share: MasticInputShare,
    ) -> bytes:
        encoded = bytes()
        encoded += input_share.key
        if input_share.seed is not None:
            encoded += input_share.seed
        if input_share.peer_joint_rand_part is not None:
            encoded += input_share.peer_joint_rand_part
        if isinstance(input_share, MasticLeaderInputShare):
            encoded += self.field.encode_vec(input_share.weight_share)
            encoded += self.field.encode_vec(input_share.proof_share)
        return encoded

    def test_vec_encode_public_share(
        self,
        correction_words: list[CorrectionWord],
    ) -> bytes:
        return self.vidpf.encode_public_share(correction_words)

    def test_vec_encode_agg_share(self, agg_share: list[F]) -> bytes:
        encoded = bytes()
        if len(agg_share) > 0:
            encoded += self.field.encode_vec(agg_share)
        return encoded

    def test_vec_encode_prep_share(
            self, prep_share: MasticPrepShare) -> bytes:
        (eval_proof, verifier_share, joint_rand_part) = prep_share
        encoded = bytes()
        encoded += eval_proof
        if joint_rand_part is not None:
            encoded += joint_rand_part
        if verifier_share is not None:
            encoded += self.field.encode_vec(verifier_share)
        return encoded

    def test_vec_encode_prep_msg(
            self, prep_message: MasticPrepMessage) -> bytes:
        encoded = bytes()
        if prep_message is not None:
            encoded += prep_message
        return encoded


##
# INSTANTIATIONS
#


class MasticCount(Mastic):
    ID = 0xFFFF0001

    # Name of the VDAF, for use in test vector filenames.
    test_vec_name = 'MasticCount'

    def __init__(self, bits: int):
        super().__init__(bits, Count(Field64))


class MasticSum(Mastic):
    ID = 0xFFFF0002

    # Name of the VDAF, for use in test vector filenames.
    test_vec_name = 'MasticSum'

    def __init__(self, bits: int, max_measurement: int):
        super().__init__(bits, Sum(Field64, max_measurement))


class MasticSumVec(Mastic):
    ID = 0xFFFF0003

    # Name of the VDAF, for use in test vector filenames.
    test_vec_name = 'MasticSumVec'

    def __init__(self, bits: int, length: int, sum_vec_bits: int, chunk_length: int):
        super().__init__(bits, SumVec(Field128, length, sum_vec_bits, chunk_length))


class MasticHistogram(Mastic):
    ID = 0xFFFF0004

    # Name of the VDAF, for use in test vector filenames.
    test_vec_name = 'MasticHistogram'

    def __init__(self, bits: int, length: int, chunk_length: int):
        super().__init__(bits, Histogram(Field128, length, chunk_length))


class MasticMultihotCountVec(Mastic):
    ID = 0xFFFF0005

    # Name of the VDAF, for use in test vector filenames.
    test_vec_name = 'MasticMultihotCountVec'

    def __init__(self, bits: int, length: int, max_weight: int, chunk_length: int):
        super().__init__(bits, MultihotCountVec(Field128, length, max_weight, chunk_length))
