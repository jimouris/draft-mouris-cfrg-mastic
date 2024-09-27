'''The Mastic VDAF'''

from typing import Optional, Sequence, TypeAlias, TypeVar, cast

from vdaf_poc.common import (byte, concat, front, to_le_bytes, vec_add,
                             vec_sub, zeros)
from vdaf_poc.field import NttField
from vdaf_poc.flp_bbcggi19 import FlpBBCGGI19, Valid
from vdaf_poc.vdaf import Vdaf
from vdaf_poc.xof import XofTurboShake128

from dst import (USAGE_JOINT_RAND, USAGE_JOINT_RAND_PART,
                 USAGE_JOINT_RAND_SEED, USAGE_PROOF_SHARE, USAGE_PROVE_RAND,
                 USAGE_QUERY_RAND, dst)
from vidpf import CorrectionWord, Vidpf

W = TypeVar("W")
R = TypeVar("R")
F = TypeVar("F", bound=NttField)

MasticAggParam: TypeAlias = tuple[
    int,            # level
    Sequence[int],  # prefixes
    bool,           # whether to do the weight check
]

MasticPublicShare: TypeAlias = tuple[
    list[CorrectionWord],   # VIDPF correction words
    Optional[list[bytes]],  # FLP joint randomness parts
]

MasticInputShare: TypeAlias = tuple[
    bytes,              # VIDPF key
    Optional[list[F]],  # FLP leader proof share
    Optional[bytes],    # FLP seed
]

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
            tuple[int, W],  # W
            MasticAggParam,
            MasticPublicShare,
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

    def __init__(self,
                 bits: int,
                 valid: Valid[W, R, F]):
        self.field = valid.field
        self.flp = FlpBBCGGI19(valid)
        self.vidpf = Vidpf(valid.field, bits, valid.MEAS_LEN)
        self.RAND_SIZE = self.vidpf.RAND_SIZE + 2 * self.xof.SEED_SIZE
        if self.flp.JOINT_RAND_LEN > 0:  # FLP leader seed
            self.RAND_SIZE += self.xof.SEED_SIZE

    def shard(self,
              measurement: tuple[int, W],
              nonce: bytes,
              rand: bytes,
              ) -> tuple[MasticPublicShare, list[MasticInputShare]]:
        if self.flp.JOINT_RAND_LEN > 0:
            return self.shard_with_joint_rand(measurement, nonce, rand)
        return self.shard_without_joint_rand(measurement, nonce, rand)

    def shard_without_joint_rand(
            self,
            measurement: tuple[int, W],
            nonce: bytes,
            rand: bytes,
    ) -> tuple[MasticPublicShare, list[MasticInputShare]]:
        (vidpf_rand, rand) = front(self.vidpf.RAND_SIZE, rand)
        (prove_rand_seed, rand) = front(self.xof.SEED_SIZE, rand)
        (helper_seed, rand) = front(self.xof.SEED_SIZE, rand)
        assert len(rand) == 0  # REMOVE ME

        (alpha, weight) = measurement
        beta = self.flp.encode(weight)

        # Generate VIDPF keys.
        (correction_words, keys) = \
            self.vidpf.gen(alpha, beta, nonce, vidpf_rand)

        # Generate FLP and split it into shares.
        prove_rand = self.prove_rand(prove_rand_seed)
        proof = self.flp.prove(beta, prove_rand, [])
        helper_proof_share = self.helper_proof_share(helper_seed)
        leader_proof_share = vec_sub(proof, helper_proof_share)

        public_share = (correction_words, None)
        input_shares = [
            (keys[0], leader_proof_share, None),
            (keys[1], None, helper_seed),
        ]
        return (public_share, input_shares)

    def shard_with_joint_rand(
            self,
            measurement: tuple[int, W],
            nonce: bytes,
            rand: bytes,
    ) -> tuple[MasticPublicShare, list[MasticInputShare]]:
        (vidpf_rand, rand) = front(self.vidpf.RAND_SIZE, rand)
        (prove_rand_seed, rand) = front(self.xof.SEED_SIZE, rand)
        (leader_seed, rand) = front(self.xof.SEED_SIZE, rand)
        (helper_seed, rand) = front(self.xof.SEED_SIZE, rand)
        assert len(rand) == 0  # REMOVE ME

        (alpha, weight) = measurement
        beta = self.flp.encode(weight)

        # Generate VIDPF keys.
        (correction_words, keys) = \
            self.vidpf.gen(alpha, beta, nonce, vidpf_rand)

        # Generate FLP joint randomness.
        joint_rand_parts = [
            self.joint_rand_part(
                0, leader_seed, keys[0], correction_words, nonce),
            self.joint_rand_part(
                1, helper_seed, keys[1], correction_words, nonce),
        ]
        joint_rand = self.joint_rand(
            self.joint_rand_seed(joint_rand_parts))

        # Generate FLP and split it into shares.
        prove_rand = self.prove_rand(prove_rand_seed)
        proof = self.flp.prove(beta, prove_rand, joint_rand)
        helper_proof_share = self.helper_proof_share(helper_seed)
        leader_proof_share = vec_sub(proof, helper_proof_share)

        public_share = (correction_words, joint_rand_parts)
        input_shares = [
            (keys[0], leader_proof_share, leader_seed),
            (keys[1], None, cast(Optional[bytes], helper_seed)),
        ]
        return (public_share, input_shares)

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
            agg_id: int,
            agg_param: MasticAggParam,
            nonce: bytes,
            public_share: MasticPublicShare,
            input_share: MasticInputShare,
    ) -> tuple[MasticPrepState, MasticPrepShare]:
        (level, prefixes, do_weight_check) = agg_param
        (key, proof_share, seed) = \
            self.expand_input_share(agg_id, input_share)
        (correction_words, joint_rand_parts) = public_share

        # Evaluate the VIDPF.
        (beta_share, out_share, eval_proof) = self.vidpf.eval(
            agg_id,
            correction_words,
            key,
            level,
            prefixes,
            nonce,
        )

        # Query the FLP if applicable.
        joint_rand_part = None
        joint_rand_seed = None
        verifier_share = None
        if do_weight_check:
            query_rand = self.query_rand(verify_key, nonce, level)
            joint_rand = []
            if self.flp.JOINT_RAND_LEN > 0:
                assert seed is not None
                assert joint_rand_parts is not None
                joint_rand_part = self.joint_rand_part(
                    agg_id, seed, key, correction_words, nonce)
                joint_rand_parts[agg_id] = joint_rand_part
                joint_rand_seed = self.joint_rand_seed(
                    joint_rand_parts)
                joint_rand = self.joint_rand(
                    self.joint_rand_seed(joint_rand_parts))
            verifier_share = self.flp.query(
                beta_share,
                proof_share,
                query_rand,
                joint_rand,
                2,
            )

        # Concatenate the output shares into one aggregatable output,
        # applying the FLP truncation algorithm on each FLP measurement
        # share.
        truncated_out_share = []
        for val_share in out_share:
            truncated_out_share += [val_share[0]] + \
                self.flp.truncate(val_share[1:])

        prep_state = (truncated_out_share, joint_rand_seed)
        prep_share = (eval_proof, verifier_share, joint_rand_part)
        return (prep_state, prep_share)

    def prep_shares_to_prep(
            self,
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
        prep_msg = self.joint_rand_seed([
            joint_rand_part_0,
            joint_rand_part_1,
        ])
        return prep_msg

    def prep_next(self,
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

    def aggregate(self,
                  agg_param: MasticAggParam,
                  out_shares: list[list[F]],
                  ) -> list[F]:
        agg_share = self.empty_agg(agg_param)
        for out_share in out_shares:
            agg_share = vec_add(agg_share, out_share)
        return agg_share

    def unshard(self,
                agg_param: MasticAggParam,
                agg_shares: list[list[F]],
                _num_measurements: int,
                ) -> list[R]:
        agg = self.empty_agg(agg_param)
        for agg_share in agg_shares:
            agg = vec_add(agg, agg_share)

        agg_result = []
        while len(agg) > 0:
            (chunk, agg) = front(self.flp.OUTPUT_LEN + 1, agg)
            meas_count = chunk[0].as_unsigned()
            agg_result.append(self.flp.decode(chunk[1:], meas_count))
        return agg_result

    def expand_input_share(
            self,
            agg_id: int,
            input_share: MasticInputShare,
    ) -> tuple[bytes, list[F], Optional[bytes]]:
        if agg_id == 0:
            (key, proof_share, seed) = input_share
            assert proof_share is not None
        else:
            (key, _leader_proof_share, seed) = input_share
            assert seed is not None
            proof_share = self.helper_proof_share(seed)
        return (key, proof_share, seed)

    def helper_proof_share(self, seed: bytes) -> list[F]:
        return self.xof.expand_into_vec(
            self.field,
            seed,
            dst(USAGE_PROOF_SHARE),
            b'',
            self.flp.PROOF_LEN,
        )

    def prove_rand(self, seed: bytes) -> list[F]:
        return self.xof.expand_into_vec(
            self.field,
            seed,
            dst(USAGE_PROVE_RAND),
            b'',
            self.flp.PROVE_RAND_LEN,
        )

    def joint_rand_part(
            self,
            agg_id: int,
            seed: bytes,
            key: bytes,
            correction_words: list[CorrectionWord],
            nonce: bytes,
    ) -> bytes:
        pub = self.vidpf.encode_public_share(correction_words)
        return self.xof.derive_seed(
            seed,
            dst(USAGE_JOINT_RAND_PART),
            byte(agg_id) + nonce + key + pub,
        )

    def joint_rand_seed(self, parts: list[bytes]) -> bytes:
        return self.xof.derive_seed(
            zeros(self.xof.SEED_SIZE),
            dst(USAGE_JOINT_RAND_SEED),
            concat(parts),
        )

    def joint_rand(self, seed: bytes) -> list[F]:
        return self.xof.expand_into_vec(
            self.field,
            seed,
            dst(USAGE_JOINT_RAND),
            b'',
            self.flp.JOINT_RAND_LEN,
        )

    def query_rand(self,
                   verify_key: bytes,
                   nonce: bytes,
                   level: int) -> list[F]:
        return self.xof.expand_into_vec(
            self.field,
            verify_key,
            dst(USAGE_QUERY_RAND),
            nonce + to_le_bytes(level, 2),
            self.flp.QUERY_RAND_LEN,
        )

    def empty_agg(self, agg_param: MasticAggParam) -> list[F]:
        (_level, prefixes, _do_weight_check) = agg_param
        agg = self.field.zeros(len(prefixes)*(1+self.flp.OUTPUT_LEN))
        return agg

    def test_vec_encode_input_share(
        self,
        input_share: MasticInputShare,
    ) -> bytes:
        (init_seed, proof_share, seed) = input_share
        encoded = bytes()
        encoded += init_seed
        if proof_share is not None:
            encoded += self.field.encode_vec(proof_share)
        if seed is not None:
            encoded += seed
        return encoded

    def test_vec_encode_public_share(
        self,
        public_share: MasticPublicShare,
    ) -> bytes:
        (correction_words, joint_rand_parts) = public_share
        encoded = bytes()
        encoded += self.vidpf.encode_public_share(correction_words)
        if joint_rand_parts is not None:
            for seed in joint_rand_parts:
                encoded += seed
        return encoded

    def test_vec_encode_agg_share(self, agg_share: list[F]) -> bytes:
        raise NotImplementedError("pick an encoding of agg share")

    def test_vec_encode_prep_share(
            self, prep_share: MasticPrepShare) -> bytes:
        raise NotImplementedError("pick an encoding of prep share")

    def test_vec_encode_prep_msg(
            self, prep_message: MasticPrepMessage) -> bytes:
        raise NotImplementedError("pick an encoding of prep msg")
