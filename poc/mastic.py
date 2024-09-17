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

Measurement = TypeVar("Measurement")
AggResult = TypeVar("AggResult")
F = TypeVar("F", bound=NttField)

MasticAggParam: TypeAlias = tuple[
    int,            # level
    Sequence[int],  # prefixes
    bool,           # whether to do the range check
]

MasticPublicShare: TypeAlias = tuple[
    list[CorrectionWord],   # VIDPF correction words
    Optional[list[bytes]],  # FLP public share
]

MasticInputShare: TypeAlias = tuple[
    bytes,              # VIDPF key
    Optional[list[F]],  # FLP leader proof share
    Optional[bytes],    # FLP seed
]

MasticPrepState: TypeAlias = tuple[
    list[F],          # Truncated output share
    Optional[bytes],  # FLP corrected joint rand seed
]

MasticPrepShare: TypeAlias = tuple[
    bytes,  # VIDPF proof
    Optional[tuple[
        list[F],          # FLP verifier share
        Optional[bytes],  # FLP joint randomness part
    ]],
]

MasticPrepMessage: TypeAlias = Optional[bytes]  # FLP joint rand seed


class Mastic(
        Vdaf[
            tuple[int, Measurement],  # Measurement
            MasticAggParam,
            MasticPublicShare,
            MasticInputShare,
            list[F],  # OutShare
            list[F],  # AggShare
            list[AggResult],  # AggResult
            MasticPrepState,
            MasticPrepShare,
            MasticPrepMessage,
        ]):

    # NOTE We'd like to make this generic, but this appears to be blocked
    # by a bug. We would add `Generic[Measurement, AggResult, X, F]` as
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
                 valid: Valid[Measurement, AggResult, F]):
        self.field = valid.field
        self.flp = FlpBBCGGI19(valid)
        self.vidpf = Vidpf(valid.field, bits, valid.MEAS_LEN)
        self.RAND_SIZE = self.vidpf.RAND_SIZE
        if self.flp.JOINT_RAND_LEN > 0:
            # flp_prove_rand_seed, flp_leader_seed, flp_helper_seed
            self.RAND_SIZE += 3 * self.xof.SEED_SIZE
        else:
            # flp_prove_rand_seed, flp_helper_seed
            self.RAND_SIZE += 2 * self.xof.SEED_SIZE

    def shard(self,
              measurement: tuple[int, Measurement],
              nonce: bytes,
              rand: bytes
              ) -> tuple[MasticPublicShare, list[MasticInputShare]]:
        if self.flp.JOINT_RAND_LEN > 0:
            return self.shard_with_joint_rand(measurement, nonce, rand)
        else:
            return self.shard_without_joint_rand(measurement, nonce, rand)

    def shard_without_joint_rand(
            self,
            measurement: tuple[int, Measurement],
            nonce: bytes,
            rand: bytes,
    ) -> tuple[MasticPublicShare, list[MasticInputShare]]:
        (vidpf_gen_rand, rand) = front(self.vidpf.RAND_SIZE, rand)
        (flp_prove_rand_seed, rand) = front(self.xof.SEED_SIZE, rand)
        (flp_helper_seed, rand) = front(self.xof.SEED_SIZE, rand)

        (alpha, meas) = measurement
        beta = self.flp.encode(meas)

        # Generate VIDPF keys.
        (vidpf_public_share, vidpf_keys) = \
            self.vidpf.gen(alpha, beta, nonce, vidpf_gen_rand)

        # Generate FLP proof shares.
        flp_prove_rand = self.prove_rand(flp_prove_rand_seed)
        flp_proof = self.flp.prove(beta, flp_prove_rand, [])
        flp_leader_proof_share = vec_sub(
            flp_proof,
            self.helper_proof_share(flp_helper_seed),
        )

        public_share = (vidpf_public_share, None)
        input_shares = [
            (vidpf_keys[0], flp_leader_proof_share, None),
            (vidpf_keys[1], None, flp_helper_seed),
        ]
        return (public_share, input_shares)

    def shard_with_joint_rand(
            self,
            measurement: tuple[int, Measurement],
            nonce: bytes,
            rand: bytes,
    ) -> tuple[MasticPublicShare, list[MasticInputShare]]:
        flp_leader_proof_share: Optional[list[F]]
        flp_public_share: Optional[list[bytes]]

        (vidpf_gen_rand, rand) = front(self.vidpf.RAND_SIZE, rand)
        (flp_prove_rand_seed, rand) = front(self.xof.SEED_SIZE, rand)
        (flp_leader_seed, rand) = front(self.xof.SEED_SIZE, rand)
        (flp_helper_seed, rand) = front(self.xof.SEED_SIZE, rand)

        (alpha, meas) = measurement
        beta = self.flp.encode(meas)

        # Generate VIDPF keys.
        (vidpf_public_share, vidpf_keys) = \
            self.vidpf.gen(alpha, beta, nonce, vidpf_gen_rand)

        # Generate FLP joint randomness.
        joint_rand_parts = []
        joint_rand_parts.append(self.joint_rand_part(
            0, flp_leader_seed, vidpf_keys[0], vidpf_public_share, nonce))
        joint_rand_parts.append(self.joint_rand_part(
            1, flp_helper_seed, vidpf_keys[1], vidpf_public_share, nonce))
        joint_rand = self.joint_rand(
            self.joint_rand_seed(joint_rand_parts))
        flp_public_share = joint_rand_parts

        # Generate FLP proof shares.
        flp_prove_rand = self.prove_rand(flp_prove_rand_seed)
        flp_proof = self.flp.prove(beta, flp_prove_rand, joint_rand)
        flp_leader_proof_share = vec_sub(
            flp_proof,
            self.helper_proof_share(flp_helper_seed),
        )

        public_share = (vidpf_public_share, flp_public_share)
        input_shares = [
            (vidpf_keys[0], flp_leader_proof_share, flp_leader_seed),
            (vidpf_keys[1], None, cast(Optional[bytes], flp_helper_seed)),
        ]
        return (public_share, input_shares)

    def is_valid(self,
                 agg_param: MasticAggParam,
                 previous_agg_params: list[MasticAggParam],
                 ) -> bool:
        (level, prefixes, do_range_check) = agg_param

        # Check that the range check is done exactly once.
        first_level_range_check = \
            (do_range_check and len(previous_agg_params) == 0) or \
            (not do_range_check and
                any(agg_param[2] for agg_param in previous_agg_params))

        # Check that the level is always larger or equal to the previous level.
        levels = list(map(
            lambda agg_param: agg_param[0],
            previous_agg_params,
        )) + [level]
        levels_non_decreasing = all(
            x <= y for (x, y) in zip(levels, levels[1:]))

        return first_level_range_check and levels_non_decreasing

    def prep_init(
            self,
            verify_key: bytes,
            agg_id: int,
            agg_param: MasticAggParam,
            nonce: bytes,
            public_share: MasticPublicShare,
            input_share: MasticInputShare,
    ) -> tuple[MasticPrepState, MasticPrepShare]:
        (level, prefixes, do_range_check) = agg_param
        (vidpf_key, flp_proof_share, flp_seed) = \
            self.expand_input_share(agg_id, input_share)
        (vidpf_public_share, flp_public_share) = public_share
        joint_rand_parts = flp_public_share

        # Evaluate the VIDPF.
        (beta_share, out_share, vidpf_proof) = self.vidpf.eval(
            agg_id,
            vidpf_public_share,
            vidpf_key,
            level,
            prefixes,
            nonce,
        )

        # Compute the FLP verifier share, if applicable.
        corrected_joint_rand_seed = None
        flp_prep_share = None
        if do_range_check:
            flp_query_rand = self.query_rand(verify_key, nonce, level)
            joint_rand_part = None
            joint_rand = []
            if self.flp.JOINT_RAND_LEN > 0:
                assert flp_seed is not None
                assert joint_rand_parts is not None
                joint_rand_part = self.joint_rand_part(
                    agg_id, flp_seed, vidpf_key,
                    vidpf_public_share, nonce)
                joint_rand_parts[agg_id] = joint_rand_part
                corrected_joint_rand_seed = self.joint_rand_seed(
                    joint_rand_parts)
                joint_rand = self.joint_rand(corrected_joint_rand_seed)
            flp_prep_share = (
                self.flp.query(
                    beta_share,
                    flp_proof_share,
                    flp_query_rand,
                    joint_rand,
                    2,
                ),
                joint_rand_part
            )

        # Concatenate the output shares into one aggregatable output, applying
        # the FLP truncation algorithm on each FLP measurement share.
        truncated_out_share = []
        for val_share in out_share:
            truncated_out_share += [val_share[0]] + \
                self.flp.truncate(val_share[1:])

        prep_state = (truncated_out_share, corrected_joint_rand_seed)
        prep_share = (vidpf_proof, flp_prep_share)
        return (prep_state, prep_share)

    def prep_shares_to_prep(
            self,
            agg_param: MasticAggParam,
            prep_shares: list[MasticPrepShare],
    ) -> MasticPrepMessage:
        (_level, _prefixes, do_range_check) = agg_param
        if len(prep_shares) != 2:
            raise ValueError('unexpected number of prep shares')

        (vidpf_proof_0, flp_prep_share_0) = prep_shares[0]
        (vidpf_proof_1, flp_prep_share_1) = prep_shares[1]
        if do_range_check:
            assert flp_prep_share_0 is not None
            assert flp_prep_share_1 is not None
            (flp_verifier_share_0, flp_jr_0) = flp_prep_share_0
            (flp_verifier_share_1, flp_jr_1) = flp_prep_share_1
            if self.flp.JOINT_RAND_LEN > 0:
                assert flp_jr_0 is not None
                assert flp_jr_1 is not None
                joint_rand_parts = [flp_jr_0, flp_jr_1]

        # Verify the VIDPF output.
        if vidpf_proof_0 != vidpf_proof_1:
            raise Exception('VIDPF verification failed')

        # Finish verifying the FLP, if applicable.
        if do_range_check:
            if flp_verifier_share_0 == None or flp_verifier_share_1 == None:
                raise ValueError('prep share with missing FLP verifier share')

            flp_verifier = vec_add(flp_verifier_share_0, flp_verifier_share_1)
            if not self.flp.decide(flp_verifier):
                raise Exception('FLP verification failed')

            joint_rand_seed = None
            if self.flp.JOINT_RAND_LEN > 0:
                joint_rand_seed = self.joint_rand_seed(joint_rand_parts)
            return joint_rand_seed

        return None

    def prep_next(self,
                  prep_state: MasticPrepState,
                  prep_msg: MasticPrepMessage,
                  ) -> list[F]:
        (out_share, corrected_joint_rand_seed) = prep_state
        if corrected_joint_rand_seed is not None:
            if prep_msg is None:
                raise ValueError('unexpected prep message')

            joint_rand_seed = prep_msg
            # If joint randomness was used, check that the value computed by the
            # Aggregators matches the value indicated by the Client.
            if joint_rand_seed != corrected_joint_rand_seed:
                raise Exception("FLP joint randomness verification failed")

        return out_share

    def aggregate(self,
                  agg_param: MasticAggParam,
                  out_shares: list[list[F]],
                  ) -> list[F]:
        (level, prefixes, _do_range_check) = agg_param
        agg_share = self.field.zeros(len(prefixes)*(1+self.flp.OUTPUT_LEN))
        for out_share in out_shares:
            agg_share = vec_add(agg_share, out_share)
        return agg_share

    def unshard(self,
                agg_param: MasticAggParam,
                agg_shares: list[list[F]],
                _num_measurements: int,
                ) -> list[AggResult]:
        (level, prefixes, _do_range_check) = agg_param
        agg = self.field.zeros(len(prefixes)*(1+self.flp.OUTPUT_LEN))
        for agg_share in agg_shares:
            agg = vec_add(agg, agg_share)

        agg_result = []
        for chunk_start in range(0, len(agg), 1+self.flp.OUTPUT_LEN):
            chunk = agg[chunk_start:chunk_start+1+self.flp.OUTPUT_LEN]
            meas_count = chunk[0].as_unsigned()
            encoded_result = chunk[1:]
            agg_result.append(self.flp.decode(encoded_result, meas_count))
        return agg_result

    def expand_input_share(
            self,
            agg_id: int,
            input_share: MasticInputShare,
    ) -> tuple[bytes, list[F], Optional[bytes]]:
        if agg_id == 0:
            (vidpf_init_seed, flp_proof_share, flp_seed) = input_share
            assert flp_proof_share is not None
        else:
            (vidpf_init_seed, _, flp_seed) = input_share
            assert flp_seed is not None
            flp_proof_share = self.helper_proof_share(flp_seed)
        return (vidpf_init_seed, flp_proof_share, flp_seed)

    def helper_proof_share(self, flp_seed: bytes) -> list[F]:
        return self.xof.expand_into_vec(
            self.field,
            flp_seed,
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

    def joint_rand_part(self,
                        agg_id: int,
                        flp_seed: bytes,
                        vidpf_key: bytes,
                        vidpf_public_share: list[CorrectionWord],
                        nonce: bytes,
                        ) -> bytes:
        return self.xof.derive_seed(
            flp_seed,
            dst(USAGE_JOINT_RAND_PART),
            byte(agg_id) + nonce + vidpf_key +
            self.vidpf.encode_public_share(vidpf_public_share),
        )

    def joint_rand_seed(self, joint_rand_parts: list[bytes]) -> bytes:
        """Derive the joint randomness seed from its parts."""
        return self.xof.derive_seed(
            zeros(self.xof.SEED_SIZE),
            dst(USAGE_JOINT_RAND_SEED),
            concat(joint_rand_parts),
        )

    def joint_rand(self, joint_rand_seed: bytes) -> list[F]:
        """Derive the joint randomness from its seed."""
        return self.xof.expand_into_vec(
            self.field,
            joint_rand_seed,
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
