'''The Mastic VDAF'''

from typing import Optional, Sequence, TypeAlias, TypeVar, cast

from vdaf_poc.common import (byte, concat, front, to_be_bytes, vec_add,
                             vec_sub, zeros)
from vdaf_poc.field import NttField
from vdaf_poc.flp_bbcggi19 import Count, FlpBBCGGI19, Sum, Valid
from vdaf_poc.vdaf import Vdaf
from vdaf_poc.xof import XofTurboShake128

from vidpf import CorrectionWord, Vidpf

Measurement = TypeVar("Measurement")
AggResult = TypeVar("AggResult")
F = TypeVar("F", bound=NttField)


# Domain separation: FLP prove randomness
USAGE_PROVE_RAND = 0

# Domain separation: FLP Helper proof share
USAGE_PROOF_SHARE = 1

# Domain separation: FLP query randomness
USAGE_QUERY_RAND = 2

# Domain separation: FLP joint randomness
USAGE_JOINT_RAND_SEED = 3

# Domain separation: FLP joint randomness parts
USAGE_JOINT_RAND_PART = 4

# Domain separation: FLP joint randomness
USAGE_JOINT_RANDOMNESS = 5

# Mastic version
VERSION = 0

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
        # TODO Figure out why unit tests fail if this code is uncommented.
        #
        # Generic[Measurement, AggResult, F],
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

    ID: int = 0xFFFFFFFF
    # TODO Use a generic XOF rather than a specific one.
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
            self.RAND_SIZE += 3 * XofTurboShake128.SEED_SIZE
        else:
            # flp_prove_rand_seed, flp_helper_seed
            self.RAND_SIZE += 2 * XofTurboShake128.SEED_SIZE

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
        (flp_prove_rand_seed, rand) = front(XofTurboShake128.SEED_SIZE, rand)
        (flp_helper_seed, rand) = front(XofTurboShake128.SEED_SIZE, rand)

        (alpha, meas) = measurement
        beta = self.flp.encode(meas)

        # Generate VIDPF keys.
        (vidpf_public_share, vidpf_keys) = \
            self.vidpf.gen(alpha, beta, nonce, vidpf_gen_rand)

        # Generate FLP proof shares.
        flp_prove_rand = XofTurboShake128.expand_into_vec(self.field,
                                                          flp_prove_rand_seed,
                                                          self.domain_separation_tag(
                                                              USAGE_PROVE_RAND),
                                                          b'',
                                                          self.flp.PROVE_RAND_LEN,
                                                          )

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
        (flp_prove_rand_seed, rand) = front(XofTurboShake128.SEED_SIZE, rand)
        (flp_leader_seed, rand) = front(XofTurboShake128.SEED_SIZE, rand)
        (flp_helper_seed, rand) = front(XofTurboShake128.SEED_SIZE, rand)

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
        flp_prove_rand = XofTurboShake128.expand_into_vec(self.field,
                                                          flp_prove_rand_seed,
                                                          self.domain_separation_tag(
                                                              USAGE_PROVE_RAND),
                                                          b'',
                                                          self.flp.PROVE_RAND_LEN,
                                                          )

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
            flp_query_rand = XofTurboShake128.expand_into_vec(
                self.field,
                verify_key,
                self.domain_separation_tag(USAGE_QUERY_RAND),
                nonce,  # TODO(cjpatton) Consider binding to agg param
                self.flp.QUERY_RAND_LEN,
            )

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
        return XofTurboShake128.expand_into_vec(
            self.field,
            flp_seed,
            self.domain_separation_tag(USAGE_PROOF_SHARE),
            b'',
            self.flp.PROOF_LEN,
        )

    def joint_rand_part(self,
                        agg_id: int,
                        flp_seed: bytes,
                        vidpf_key: bytes,
                        vidpf_public_share: list[CorrectionWord],
                        nonce: bytes,
                        ) -> bytes:
        return XofTurboShake128.derive_seed(
            flp_seed,
            self.domain_separation_tag(USAGE_JOINT_RAND_PART),
            byte(agg_id) + nonce + vidpf_key +
            self.vidpf.encode_public_share(vidpf_public_share),
        )

    def joint_rand_seed(self, joint_rand_parts: list[bytes]) -> bytes:
        """Derive the joint randomness seed from its parts."""
        return XofTurboShake128.derive_seed(
            zeros(XofTurboShake128.SEED_SIZE),
            self.domain_separation_tag(USAGE_JOINT_RAND_SEED),
            concat(joint_rand_parts),
        )

    def joint_rand(self, joint_rand_seed: bytes) -> list[F]:
        """Derive the joint randomness from its seed."""
        return XofTurboShake128.expand_into_vec(
            self.field,
            joint_rand_seed,
            self.domain_separation_tag(USAGE_JOINT_RANDOMNESS),
            b'',
            self.flp.JOINT_RAND_LEN,
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
        # TODO(cjpatton) Decide on a serialization format for Mastic.
        return b'dummy agg share'

    def test_vec_encode_prep_share(
            self, prep_share: MasticPrepShare) -> bytes:
        # TODO(cjpatton) Decide on a serialization format for Mastic.
        return b'dummy prep share'

    def test_vec_encode_prep_msg(
            self, prep_message: MasticPrepMessage) -> bytes:
        # TODO(cjpatton) Decide on a serialization format for Mastic.
        return b'dummy prep message'

    def domain_separation_tag(self, usage) -> bytes:
        return concat([
            to_be_bytes(VERSION, 1),
            to_be_bytes(self.ID, 4),
            to_be_bytes(usage, 2),
        ])


def get_reports_from_measurements(mastic, measurements):
    from vdaf_poc.common import gen_rand

    reports = []
    for measurement in measurements:
        nonce = gen_rand(16)
        rand = gen_rand(mastic.RAND_SIZE)
        (public_share, input_shares) = mastic.shard(measurement, nonce, rand)
        reports.append((nonce, public_share, input_shares))
    return reports


def get_threshold(thresholds, prefix, level):
    '''
    Return the threshold of the given (prefix, level) if the tuple exists. If
    not, check if any of its prefixes exist. If not, return the default
    threshold.
    '''
    while level > 0:
        if (prefix, level) in thresholds:
            return thresholds[(prefix, level)]
        prefix >>= 1
        level -= 1
    return thresholds['default']  # Return the default threshold


def compute_heavy_hitters(mastic, bits, thresholds, reports):
    from vdaf_poc.common import gen_rand

    verify_key = gen_rand(16)

    prefixes = [0, 1]
    prev_agg_params = []
    heavy_hitters = []
    for level in range(bits):
        agg_param = (level, prefixes, level == 0)
        assert mastic.is_valid(agg_param, prev_agg_params)

        # Aggregators prepare reports for aggregation.
        out_shares = [[], []]
        for (nonce, public_share, input_shares) in reports:
            # Each aggregator broadcast its prep share; ...
            (prep_state, prep_shares) = zip(*[
                mastic.prep_init(
                    verify_key,
                    agg_id,
                    agg_param,
                    nonce,
                    public_share,
                    input_shares[agg_id]) for agg_id in [0, 1]
            ])

            # computes the prep message; ...
            prep_msg = mastic.prep_shares_to_prep(agg_param, prep_shares)

            # and computes its output share.
            for agg_id in [0, 1]:
                out_shares[agg_id].append(
                    mastic.prep_next(prep_state[agg_id], prep_msg))

        # Aggregators aggregate their output shares.
        agg_shares = [
            mastic.aggregate(agg_param, out_shares[agg_id]) for agg_id in [0, 1]
        ]

        # Collector computes the aggregate result.
        agg_result = mastic.unshard(agg_param, agg_shares, len(reports))
        prev_agg_params.append(agg_param)

        if level < bits - 1:
            # Compute the next set of candidate prefixes.
            next_prefixes = []
            for (prefix, count) in zip(prefixes, agg_result):
                threshold = get_threshold(thresholds, prefix, level)
                if count >= threshold:
                    next_prefixes.append(prefix << 1)
                    next_prefixes.append((prefix << 1) | 1)
            prefixes = next_prefixes
        else:
            for (prefix, count) in zip(prefixes, agg_result):
                threshold = get_threshold(thresholds, prefix, level)
                if count >= threshold:
                    heavy_hitters.append(prefix)
    return heavy_hitters


def example_weighted_heavy_hitters_mode():
    from vdaf_poc.field import Field64

    bits = 4
    mastic = Mastic(bits, Count(Field64))

    # Clients shard their measurements. Each measurement is comprised of
    # `(alpha, beta)` where `alpha` is the payload string and `beta` is its
    # weight. Here the weight is simply a counter (either `0` or `1`).
    measurements = [
        (0b1001, 1),
        (0b0000, 1),
        (0b0000, 0),
        (0b0000, 1),
        (0b1001, 1),
        (0b0000, 1),
        (0b1100, 1),
        (0b0011, 1),
        (0b1111, 0),
        (0b1111, 0),
        (0b1111, 1),
    ]

    reports = get_reports_from_measurements(mastic, measurements)

    thresholds = {
        'default': 2,
    }

    # Collector and Aggregators compute the weighted heavy hitters.
    heavy_hitters = compute_heavy_hitters(mastic, bits, thresholds, reports)
    print("Weighted heavy-hitters:",
          list(map(lambda x: bin(x), heavy_hitters)))
    assert heavy_hitters == [0, 9]


def example_weighted_heavy_hitters_mode_with_different_thresholds():
    from vdaf_poc.field import Field64

    bits = 4
    mastic = Mastic(bits, Count(Field64))

    # Clients shard their measurements. Each measurement is comprised of
    # `(alpha, beta)` where `alpha` is the payload string and `beta` is its
    # weight. Here the weight is simply a counter (either `0` or `1`).
    measurements = [
        (0b0000, 1),
        (0b0001, 1),
        (0b1001, 1),
        (0b1001, 1),
        (0b1010, 1),
        (0b1010, 1),
        (0b1111, 1),
        (0b1111, 1),
        (0b1111, 1),
        (0b1111, 1),
        (0b1111, 1),
    ]

    reports = get_reports_from_measurements(mastic, measurements)

    # (prefix, level): threshold
    # Note that levels start from zero
    thresholds = {
        'default': 2,
        (0b00, 1): 1,
        (0b10, 1): 3,
        (0b11, 1): 5,
    }

    # Collector and Aggregators compute the weighted heavy hitters.
    heavy_hitters = compute_heavy_hitters(mastic, bits, thresholds, reports)
    print("Weighted heavy-hitters with different thresholds:",
          list(map(lambda x: bin(x), heavy_hitters)))
    assert heavy_hitters == [0, 1, 15]


def example_attribute_based_metrics_mode():
    import hashlib

    from vdaf_poc.common import gen_rand
    from vdaf_poc.field import Field64

    bits = 8
    mastic = Mastic(bits, Sum(Field64, 3))
    verify_key = gen_rand(16)

    def h(attr):
        """
        Hash the attribute to a fixed-size string whose size matches the
        bit-size for our instance of Mastic. For testing purposes, we truncate
        to the first `8` bits of the hash; in practice we would need collision
        resistance. Mastic should be reasonably fast even for `bits == 256`
        (the same as SHA-3).
        """
        assert bits == 8
        sha3 = hashlib.sha3_256()
        sha3.update(attr.encode('ascii'))
        return sha3.digest()[0]

    # Clients shard their measurements. Each measurement is comprised of
    # (`alpha`, `beta`) where `beta` is the Client's contribution to the
    # aggregate with attribute `alpha`.
    #
    # In this example, each Client casts a "vote" (between '0' and '3') and
    # attributes their vote with their home country.
    measurements = [
        ('United States', 1),
        ('Greece', 1),
        ('United States', 2),
        ('Greece', 0),
        ('United States', 0),
        ('India', 1),
        ('Greece', 0),
        ('United States', 1),
        ('Greece', 1),
        ('Greece', 3),
        ('Greece', 1),
    ]
    reports = []
    for (attr, vote) in measurements:
        nonce = gen_rand(16)
        rand = gen_rand(mastic.RAND_SIZE)
        (public_share, input_shares) = mastic.shard(
            (h(attr), vote),
            nonce,
            rand,
        )
        reports.append((nonce, public_share, input_shares))

    # Aggregators aggregate the reports, breaking them down by home country.
    attrs = [
        'Greece',
        'Mexico',
        'United States',
    ]
    agg_param = (bits-1, list(map(lambda attr: h(attr), attrs)), True)
    assert mastic.is_valid(agg_param, [])

    # Aggregators prepare reports for aggregation.
    out_shares = [[], []]
    for (nonce, public_share, input_shares) in reports:
        # Each aggregator broadcast its prep share; ...
        (prep_state, prep_shares) = zip(*[
            mastic.prep_init(
                verify_key,
                agg_id,
                agg_param,
                nonce,
                public_share,
                input_shares[agg_id]) for agg_id in [0, 1]
        ])

        # computes the prep message; ...
        prep_msg = mastic.prep_shares_to_prep(agg_param, prep_shares)

        # and computes its output share.
        for agg_id in [0, 1]:
            out_shares[agg_id].append(
                mastic.prep_next(prep_state[agg_id], prep_msg))

    # Aggregators aggregate their output shares.
    agg_shares = [
        mastic.aggregate(agg_param, out_shares[agg_id]) for agg_id in [0, 1]
    ]

    # Collector computes the aggregate result.
    agg_result = mastic.unshard(agg_param, agg_shares, len(measurements))
    print('Election results:', list(zip(attrs, agg_result)))
    assert agg_result == [6, 0, 4]


def example_poplar1_overhead():
    import math

    from vdaf_poc.common import gen_rand
    from vdaf_poc.field import Field64, Field128
    from vdaf_poc.flp_bbcggi19 import Histogram
    from vdaf_poc.vdaf_poplar1 import Poplar1
    from vdaf_poc.vdaf_prio3 import Prio3Histogram

    nonce = gen_rand(16)

    cls = Poplar1(256)
    (public_share, input_shares) = cls.shard(0, nonce, gen_rand(cls.RAND_SIZE))
    b = 0
    p = len(cls.test_vec_encode_public_share(public_share))
    b += p
    print('Poplar1(256) public share len:', p)
    p = len(cls.test_vec_encode_input_share(input_shares[0]))
    b += p
    print('Poplar1(256) input share 0 len:', p)
    p = len(cls.test_vec_encode_input_share(input_shares[1]))
    b += p
    print('Poplar1(256) input share 1 len:', p)
    poplar1_bytes_uploaded = b

    cls = Mastic(256, Count(Field64))
    (public_share, input_shares) = cls.shard((0, 0),
                                             nonce,
                                             gen_rand(cls.RAND_SIZE))
    b = 0
    p = len(cls.test_vec_encode_public_share(public_share))
    b += p
    print('Mastic(256,Count()) public share len:', p)
    p = len(cls.test_vec_encode_input_share(input_shares[0]))
    b += p
    print('Mastic(256,Count()) input share 0 len:', p)
    p = len(cls.test_vec_encode_input_share(input_shares[1]))
    b += p
    print('Mastic(256,Count()) input share 1 len:', p)
    mastic_count_bytes_uploaded = b

    cls = Mastic(256, Sum(Field64, 8))
    (public_share, input_shares) = cls.shard((0, 0),
                                             nonce,
                                             gen_rand(cls.RAND_SIZE))
    b = 0
    p = len(cls.test_vec_encode_public_share(public_share))
    b += p
    print('Mastic(256,Sum(8)) public share len:', p)
    p = len(cls.test_vec_encode_input_share(input_shares[0]))
    b += p
    print('Mastic(256,Sum(8)) input share 0 len:', p)
    p = len(cls.test_vec_encode_input_share(input_shares[1]))
    b += p
    print('Mastic(256,Sum(8)) input share 1 len:', p)
    mastic_sum8_bytes_uploaded = b

    print('Mastic(256,Count()) overhead for Poplar1(256): {:.2f}%'.format(
        mastic_count_bytes_uploaded / poplar1_bytes_uploaded * 100))
    print('Mastic(256,Sum(8)) overhead for Mastic(256,Count()): {:.2f}%'.format(
        mastic_sum8_bytes_uploaded / mastic_count_bytes_uploaded * 100))

    cls = Mastic(32, Histogram(Field128, 100, 10))
    (public_share, input_shares) = cls.shard((0, 0),
                                             nonce,
                                             gen_rand(cls.RAND_SIZE))
    b = 0
    p = len(cls.test_vec_encode_public_share(public_share))
    b += p
    print('Mastic(32,Histogram(100, 10)) public share len:', p)
    p = len(cls.test_vec_encode_input_share(input_shares[0]))
    b += p
    print('Mastic(32,Histogram(100, 10)) input share 0 len:', p)
    p = len(cls.test_vec_encode_input_share(input_shares[1]))
    b += p
    print('Mastic(32,Histogram(100, 10)) input share 1 len:', p)
    print('Mastic(32,Histogram(100, 10)) total upload len:', b)
    mastic_hist_bytes_uploaded = b

    length = 100 * 100  # base histogram length * number of attributes
    chunk_length = math.floor(math.sqrt(length))
    cls = Prio3Histogram(2, length, chunk_length)
    (public_share, input_shares) = cls.shard(0, nonce, gen_rand(cls.RAND_SIZE))
    b = 0
    p = len(cls.test_vec_encode_public_share(public_share))
    b += p
    print('Prio3Histogram({}, {}) public share len:'.format(
        length, chunk_length), p)
    p = len(cls.test_vec_encode_input_share(input_shares[0]))
    b += p
    print('Prio3Histogram({}, {}) input share 0 len:'.format(
        length, chunk_length), p)
    p = len(cls.test_vec_encode_input_share(input_shares[1]))
    b += p
    print('Prio3Histogram({}, {}) input share 1 len:'.format(
        length, chunk_length), p)
    print('Prio3Histogram({}, {}) total upload len:'.format(
        length, chunk_length), b)
    prio3_hist_bytes_uploaded = b

    print(prio3_hist_bytes_uploaded / mastic_hist_bytes_uploaded)


# TODO Move this to a separate file.
if __name__ == '__main__':
    example_poplar1_overhead()
    example_weighted_heavy_hitters_mode()
    example_attribute_based_metrics_mode()
    example_weighted_heavy_hitters_mode_with_different_thresholds()
