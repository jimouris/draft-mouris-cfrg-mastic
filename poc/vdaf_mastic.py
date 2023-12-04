'''The Mastic VDAF'''

import sys

sys.path.append('draft-irtf-cfrg-vdaf/poc')  # nopep8


from typing import Optional

from common import Unsigned, byte, concat, front, vec_add, vec_sub, zeros
from flp_generic import FlpGeneric
from vdaf import Vdaf, test_vdaf
from xof import XofShake128

from vidpf import Vidpf

# Domain separation: FLP prove randomness
USAGE_PROVE_RAND = 0

# Domain separation: FLP Helper proof share
USAGE_PROOF_SHARE = 1

# Domain separation: FLP query randomness
USAGE_QUERY_RAND = 2

# Domain separation: FLP joint randomness
USAGE_JOINT_RAND_SEED = 3

# Domain separation: FLP joint randomness
USAGE_JOINT_RAND_PART = 4

# Domain separation: FLP joint randomness
USAGE_JOINT_RANDOMNESS = 5


class Mastic(Vdaf):
    # Operational types and parameters.
    Field = None  # Set by `with_params()`
    Vidpf = None  # Set by `with_params()`
    Flp = None  # Set by `with_params()`
    Xof = XofShake128

    # Parameters required by `Vdaf`.
    ID: Unsigned = 0xFFFFFFFF
    VERIFY_KEY_SIZE = Xof.SEED_SIZE
    NONCE_SIZE = 16
    RAND_SIZE = None  # Set by `with_params()`
    SHARES = 2
    ROUNDS = 1

    # Types required by `Vdaf`
    AggParam = None  # TODO(cjpatton)
    PublicShare = None  # TODO(cjpatton)
    InputShare = None  # TODO(cjpatton)
    PrepMessage = None

    @classmethod
    def shard(cls, measurement, nonce, rand):
        if cls.Flp.JOINT_RAND_LEN > 0:
            return cls.shard_with_joint_rand(measurement, nonce, rand)
        else:
            return cls.shard_without_joint_rand(measurement, nonce, rand)

    @classmethod
    def shard_without_joint_rand(cls, measurement, nonce, rand):
        (vidpf_gen_rand, rand) = front(cls.Vidpf.RAND_SIZE, rand)
        (flp_prove_rand_seed, rand) = front(cls.Xof.SEED_SIZE, rand)
        (flp_helper_seed, rand) = front(cls.Xof.SEED_SIZE, rand)

        (alpha, meas) = measurement
        beta = cls.Flp.encode(meas)

        # Generate VIDPF keys.
        (vidpf_init_seed, vidpf_correction_words, vidpf_cs_proofs) = \
            cls.Vidpf.gen(alpha, beta, nonce, vidpf_gen_rand)
        public_share = ((vidpf_correction_words, vidpf_cs_proofs), None)

        # Generate FLP proof shares.
        flp_prove_rand = cls.Xof.expand_into_vec(cls.Field,
                                                 flp_prove_rand_seed,
                                                 cls.domain_separation_tag(
                                                     USAGE_PROVE_RAND),
                                                 b'',
                                                 cls.Flp.PROVE_RAND_LEN,
                                                 )

        flp_proof = cls.Flp.prove(beta, flp_prove_rand, [])
        flp_leader_proof_share = vec_sub(
            flp_proof,
            cls.helper_proof_share(flp_helper_seed),
        )

        input_shares = [
            (vidpf_init_seed[0], flp_leader_proof_share, None),
            (vidpf_init_seed[1], None, flp_helper_seed),
        ]
        return (public_share, input_shares)

    @classmethod
    def shard_with_joint_rand(cls, measurement, nonce, rand):
        (vidpf_gen_rand, rand) = front(cls.Vidpf.RAND_SIZE, rand)
        (flp_prove_rand_seed, rand) = front(cls.Xof.SEED_SIZE, rand)
        (flp_leader_seed, rand) = front(cls.Xof.SEED_SIZE, rand)
        (flp_helper_seed, rand) = front(cls.Xof.SEED_SIZE, rand)

        (alpha, meas) = measurement
        beta = cls.Flp.encode(meas)

        # Generate VIDPF keys.
        (vidpf_init_seed, vidpf_correction_words, vidpf_cs_proofs) = \
            cls.Vidpf.gen(alpha, beta, nonce, vidpf_gen_rand)
        vidpf_public_share = (vidpf_correction_words, vidpf_cs_proofs)

        # Generate FLP joint randomness.
        joint_rand_parts = []
        joint_rand_parts.append(cls.joint_rand_part(
            0, flp_leader_seed, vidpf_init_seed[0], nonce))
        joint_rand_parts.append(cls.joint_rand_part(
            1, flp_helper_seed, vidpf_init_seed[1], nonce))
        joint_rand = cls.joint_rand(
            cls.joint_rand_seed(joint_rand_parts))
        flp_public_share = joint_rand_parts

        # Generate FLP proof shares.
        flp_prove_rand = cls.Xof.expand_into_vec(cls.Field,
                                                 flp_prove_rand_seed,
                                                 cls.domain_separation_tag(
                                                     USAGE_PROVE_RAND),
                                                 b'',
                                                 cls.Flp.PROVE_RAND_LEN,
                                                 )

        flp_proof = cls.Flp.prove(beta, flp_prove_rand, joint_rand)
        flp_leader_proof_share = vec_sub(
            flp_proof,
            cls.helper_proof_share(flp_helper_seed),
        )

        input_shares = [
            (vidpf_init_seed[0], flp_leader_proof_share, flp_leader_seed),
            (vidpf_init_seed[1], None, flp_helper_seed),
        ]
        public_share = (
            vidpf_public_share,
            flp_public_share
        )
        return (public_share, input_shares)

    @classmethod
    def is_valid(cls, agg_param, previous_agg_params):
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

    @classmethod
    def prep_init(cls, verify_key, agg_id, agg_param,
                  nonce, public_share, input_share):
        (level, prefixes, do_range_check) = agg_param
        (vidpf_init_seed, flp_proof_share, flp_blind) = \
            cls.expand_input_share(agg_id, input_share)
        (vidpf_public_share, flp_public_share) = public_share
        (vidpf_correction_words, vidpf_cs_proofs) = vidpf_public_share
        joint_rand_parts = flp_public_share

        # Evaluate the VIDPF.
        (beta_share, out_share, vidpf_proof) = cls.Vidpf.eval(
            agg_id,
            vidpf_correction_words,
            vidpf_cs_proofs,
            vidpf_init_seed,
            level,
            prefixes,
            nonce,
        )

        # Compute the FLP verifier share, if applicable.
        flp_verifier_share = None
        if do_range_check:
            flp_query_rand = cls.Xof.expand_into_vec(
                cls.Flp.Field,
                verify_key,
                cls.domain_separation_tag(USAGE_QUERY_RAND),
                nonce,  # TODO(cjpatton) Consider binding to agg param
                cls.Flp.QUERY_RAND_LEN,
            )

            corrected_joint_rand_seed, joint_rand_part = None, None
            joint_rand = []
            if cls.Flp.JOINT_RAND_LEN > 0:
                joint_rand_part = cls.joint_rand_part(
                    agg_id, flp_blind, vidpf_init_seed, nonce)
                joint_rand_parts[agg_id] = joint_rand_part
                corrected_joint_rand_seed = cls.joint_rand_seed(
                    joint_rand_parts)
                joint_rand = cls.joint_rand(corrected_joint_rand_seed)
            flp_verifier_share = (
                cls.Flp.query(
                    beta_share,
                    flp_proof_share,
                    flp_query_rand,
                    joint_rand,
                    cls.SHARES
                ),
                joint_rand_part
            )
        prep_state = [do_range_check]

        # Concatenate the output shares into one aggregatable output, applying
        # the FLP truncation algorithm on each FLP measurement share.
        truncated_out_share = []
        for val_share in out_share:
            truncated_out_share += [val_share[0]] + \
                cls.Flp.truncate(val_share[1:])

        if do_range_check:
            prep_state += [(truncated_out_share, corrected_joint_rand_seed)]
        else:
            prep_state.append(truncated_out_share)
        prep_share = (vidpf_proof, flp_verifier_share)
        return (prep_state, prep_share)

    @classmethod
    def prep_shares_to_prep(cls, agg_param, prep_shares):
        (_level, _prefixes, do_range_check) = agg_param
        if len(prep_shares) != 2:
            raise ValueError('unexpected number of prep shares')

        (vidpf_proof_0, flp_verifier_share_0) = prep_shares[0]
        (vidpf_proof_1, flp_verifier_share_1) = prep_shares[1]
        if do_range_check:
            flp_verifier_share_0, flp_jr_0 = flp_verifier_share_0
            flp_verifier_share_1, flp_jr_1 = flp_verifier_share_1
            if cls.Flp.JOINT_RAND_LEN > 0:
                joint_rand_parts = [flp_jr_0, flp_jr_1]

        # Verify the VIDPF output.
        if vidpf_proof_0 != vidpf_proof_1:
            raise Exception('VIDPF verification failed')

        # Finish verifying the FLP, if applicable.
        if do_range_check:
            if flp_verifier_share_0 == None or flp_verifier_share_1 == None:
                raise ValueError('prep share with missing FLP verifier share')

            flp_verifier = vec_add(flp_verifier_share_0, flp_verifier_share_1)
            if not cls.Flp.decide(flp_verifier):
                raise Exception('FLP verification failed')

            joint_rand_seed = None
            if cls.Flp.JOINT_RAND_LEN > 0:
                joint_rand_seed = cls.joint_rand_seed(joint_rand_parts)
            return joint_rand_seed

        return None

    @classmethod
    def prep_next(_cls, prep_state, prep_msg):
        (do_range_check, prep) = prep_state
        if do_range_check:
            joint_rand_seed = prep_msg
            (out_share, corrected_joint_rand_seed) = prep
            # If joint randomness was used, check that the value computed by the
            # Aggregators matches the value indicated by the Client.
            if joint_rand_seed != corrected_joint_rand_seed:
                raise Exception("FLP joint randomness verification failed")

            return out_share

        if prep_msg != None:
            raise ValueError('unexpected prep message')
        return prep

    @classmethod
    def aggregate(cls, agg_param, out_shares):
        (level, prefixes, _do_range_check) = agg_param
        agg_share = cls.Field.zeros(len(prefixes)*(1+cls.Flp.OUTPUT_LEN))
        for out_share in out_shares:
            agg_share = vec_add(agg_share, out_share)
        return agg_share

    @classmethod
    def unshard(cls, agg_param,
                agg_shares, _num_measurements):
        (level, prefixes, _do_range_check) = agg_param
        agg = cls.Field.zeros(len(prefixes)*(1+cls.Flp.OUTPUT_LEN))
        for agg_share in agg_shares:
            agg = vec_add(agg, agg_share)

        agg_result = []
        for chunk_start in range(0, len(agg), 1+cls.Flp.OUTPUT_LEN):
            chunk = agg[chunk_start:chunk_start+1+cls.Flp.OUTPUT_LEN]
            meas_count = chunk[0].as_unsigned()
            encoded_result = chunk[1:]
            agg_result.append(cls.Flp.decode(encoded_result, meas_count))
        return agg_result

    @classmethod
    def expand_input_share(cls, agg_id, input_share):
        (vidpf_init_seed, flp_proof_share, flp_seed) = input_share
        if agg_id > 0:
            flp_proof_share = cls.helper_proof_share(flp_seed)
        return (vidpf_init_seed, flp_proof_share, flp_seed)

    @classmethod
    def helper_proof_share(cls, flp_helper_proof_share_seed):
        return cls.Xof.expand_into_vec(
            cls.Field,
            flp_helper_proof_share_seed,
            cls.domain_separation_tag(USAGE_PROOF_SHARE),
            b'',
            cls.Flp.PROOF_LEN,
        )

    @classmethod
    def joint_rand_part(cls, agg_id, k_blind, inp_share, nonce):
        return cls.Xof.derive_seed(
            k_blind,
            cls.domain_separation_tag(USAGE_JOINT_RAND_PART),
            byte(agg_id) + nonce + inp_share,
        )

    @classmethod
    def joint_rand_seed(cls, joint_rand_parts):
        """Derive the joint randomness seed from its parts."""
        return cls.Xof.derive_seed(
            zeros(cls.Xof.SEED_SIZE),
            cls.domain_separation_tag(USAGE_JOINT_RAND_SEED),
            concat(joint_rand_parts),
        )

    @classmethod
    def joint_rand(cls, joint_rand_seed):
        """Derive the joint randomness from its seed."""
        return cls.Xof.expand_into_vec(
            cls.Flp.Field,
            joint_rand_seed,
            cls.domain_separation_tag(USAGE_JOINT_RANDOMNESS),
            b'',
            cls.Flp.JOINT_RAND_LEN,
        )

    @classmethod
    def do_range_check(cls, agg_param):
        (level, _prefixes) = agg_param
        return (level == cls.Vidpf.BITS-1
                and not cls.Vidpf.INCREMENTAL_MODE) or level == 0

    @classmethod
    def test_vec_encode_input_share(Vdaf, input_share):
        # TODO(cjpatton) Decide on a serialization format for Mastic.
        return b'dummy input share'

    @classmethod
    def test_vec_encode_public_share(Vdaf, public_share):
        # TODO(cjpatton) Decide on a serialization format for Mastic.
        return b'dummy public share'

    @classmethod
    def test_vec_encode_agg_share(Vdaf, agg_share):
        # TODO(cjpatton) Decide on a serialization format for Mastic.
        return b'dummy agg share'

    @classmethod
    def test_vec_encode_prep_share(Vdaf, prep_share):
        # TODO(cjpatton) Decide on a serialization format for Mastic.
        return b'dummy prep share'

    @classmethod
    def test_vec_encode_prep_msg(Vdaf, prep_message):
        # TODO(cjpatton) Decide on a serialization format for Mastic.
        return b'dummy prep message'

    @classmethod
    def with_params(cls, bits, validity_circuit):

        class MasticWithParams(cls):
            # Operational types and parameters.
            Flp = FlpGeneric(validity_circuit)
            Field = Flp.Field
            Vidpf = Vidpf.with_params(Flp.Field, bits, Flp.MEAS_LEN)
            # TODO(cjpatton) Add test_vec_name to base spec for the validity
            # circuit so that we can call it here.
            test_vec_name = 'Mastic({}, {})'.format(bits, validity_circuit)

            RAND_SIZE = Vidpf.RAND_SIZE
            if Flp.JOINT_RAND_LEN > 0:
                # flp_prove_rand_seed, flp_helper_seed
                RAND_SIZE += 2 * XofShake128.SEED_SIZE
            else:
                # flp_prove_rand_seed, flp_leader_seed, flp_helper_seed
                RAND_SIZE += 3 * XofShake128.SEED_SIZE

            # `alpha` and the un-encoded `beta`.
            Measurement = tuple[Unsigned,
                                Flp.Measurement]
            AggShare = list[Field]
            AggResult = list[Flp.AggResult]
            PrepState = list[Field]

            # Concatenation of FLP truncated outputs.
            #
            # TODO(cjpatton) Maybe represent this instead as a list of lists.
            # This is currently incompatible with the test vector generation
            # logic.
            OutShare = list[Field]

            # Level proof and optional verifier share.
            PrepShare = tuple[bytes,
                              Optional[list[Field]]]

        return MasticWithParams


def test_valid_agg_params():
    mastic = Mastic.with_params(4, Count())

    assert mastic.is_valid(
        (0, (0,), True),
        [],
    )

    assert mastic.is_valid(
        (2, (0b100,), True),
        [],
    )

    # Expect invalid because we never do the range check.
    assert not mastic.is_valid(
        (0, (0,), False),
        [],
    )

    assert mastic.is_valid(
        (1, (0b10,), False),
        [
            (0, (0,), True),
        ],
    )

    # Expect invalid because we do the range check twice.
    assert not mastic.is_valid(
        (1, (0b10,), True),
        [
            (0, (0,), True),
        ],
    )

    # Expect invalid because we don't do the range check at the first level.
    assert not mastic.is_valid(
        (1, (0b10,), True),
        [
            (0, (0,), False),
        ],
    )

    # Expect invalid because we never do the range check.
    assert not mastic.is_valid(
        (1, (0b10,), False),
        [
            (0, (0,), False),
        ],
    )

    # Expect invalid because the level decreases.
    assert not mastic.is_valid(
        (1, (0b10,), False),
        [
            (2, (0b100,), True),
        ],
    )

    assert mastic.is_valid(
        (2, (0b101,), False),
        [
            (2, (0b100,), True),
        ],
    )


def get_reports_from_measurements(mastic, measurements):
    from common import gen_rand

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
    from common import gen_rand

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
    from flp_generic import Count
    bits = 4
    mastic = Mastic.with_params(bits, Count())

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
    from flp_generic import Count
    bits = 4
    mastic = Mastic.with_params(bits, Count())

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


def example_aggregation_by_labels_mode():
    import hashlib

    from common import gen_rand
    bits = 8
    mastic = Mastic.with_params(bits, Sum(2))
    verify_key = gen_rand(16)

    def h(label):
        """
        Hash the label to a fixed-size string whose size matches the bit-size
        for our instance of Mastic. For testing purposes, we truncate to the
        first `8` bits of the hash; in practice we would need collision
        resistance. Mastic should be reasonably fast even for `bits == 256`
        (the same as SHA-3).
        """
        assert bits == 8
        sha3 = hashlib.sha3_256()
        sha3.update(label.encode('ascii'))
        return sha3.digest()[0]

    # Clients shard their measurements. Each measurement is comprised of
    # (`alpha`, `beta`) where `beta` is the Client's contribution to the
    # aggregate with label `alpha`.
    #
    # In this example, each Client casts a "vote" (between '0' and '3') and
    # labels their vote with their home country.
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
    for (label, vote) in measurements:
        nonce = gen_rand(16)
        rand = gen_rand(mastic.RAND_SIZE)
        (public_share, input_shares) = mastic.shard(
            (h(label), vote),
            nonce,
            rand,
        )
        reports.append((nonce, public_share, input_shares))

    # Aggregators aggregate the reports, breaking them down by home country.
    labels = [
        'Greece',
        'Mexico',
        'United States',
    ]
    agg_param = (bits-1, list(map(lambda label: h(label), labels)), True)
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
    print('Election results:', list(zip(labels, agg_result)))
    assert agg_result == [6, 0, 4]


if __name__ == '__main__':
    from common import from_be_bytes
    from flp_generic import Count, Sum

    example_weighted_heavy_hitters_mode()
    example_aggregation_by_labels_mode()
    example_weighted_heavy_hitters_mode_with_different_thresholds()

    test_vdaf(
        Mastic.with_params(2, Count()),
        (0, (0b0, 0b1), True),
        [
            (0b10, 1),
            (0b00, 1),
            (0b11, 1),
            (0b01, 1),
            (0b11, 1),
        ],
        [2, 3],
    )

    test_vdaf(
        Mastic.with_params(2, Count()),
        (1, (0b00, 0b01), True),
        [
            (0b10, 1),
            (0b00, 1),
            (0b11, 1),
            (0b01, 1),
            (0b01, 0),
        ],
        [1, 1],
    )

    test_vdaf(
        Mastic.with_params(16, Count()),
        (14, (0b111100001111000,), True),
        [
            (0b1111000011110000, 0),
            (0b1111000011110001, 1),
            (0b0111000011110000, 0),
            (0b1111000011110010, 1),
            (0b1111000000000000, 0),
        ],
        [1],
    )

    test_vdaf(
        Mastic.with_params(256, Count()),
        (
            63,
            (
                from_be_bytes(b'00000000'),
                from_be_bytes(b'01234567'),
            ),
            True,
        ),
        [
            (from_be_bytes(b'0123456789abcdef0123456789abcdef'), 1),
            (from_be_bytes(b'01234567890000000000000000000000'), 1),
        ],
        [0, 2],
    )

    test_vdaf(
        Mastic.with_params(2, Sum(3)),
        (0, (0b0, 0b1), True),
        [
            (0b10, 1),
            (0b00, 6),
            (0b11, 7),
            (0b01, 5),
            (0b11, 2),
        ],
        [11, 10],
    )

    test_vdaf(
        Mastic.with_params(2, Sum(2)),
        (1, (0b00, 0b01), True),
        [
            (0b10, 3),
            (0b00, 2),
            (0b11, 0),
            (0b01, 1),
            (0b01, 2),
        ],
        [2, 3],
    )

    test_vdaf(
        Mastic.with_params(16, Sum(1)),
        (14, (0b111100001111000,), True),
        [
            (0b1111000011110000, 0),
            (0b1111000011110001, 1),
            (0b0111000011110000, 0),
            (0b1111000011110010, 1),
            (0b1111000000000000, 0),
        ],
        [1],
    )

    test_vdaf(
        Mastic.with_params(256, Sum(8)),
        (
            63,
            (
                from_be_bytes(b'00000000'),
                from_be_bytes(b'01234567'),
            ),
            True,
        ),
        [
            (from_be_bytes(b'0123456789abcdef0123456789abcdef'), 121),
            (from_be_bytes(b'01234567890000000000000000000000'), 6),
        ],
        [0, 127],
    )

    # TODO(cjpatton) Add tests for a circuit with `MEAS_LEN > 1` so that we can
    # assess whether any `Vidpf` encode assumes `len(beta) == 1`.

    test_valid_agg_params()
