import sys
sys.path.append('draft-irtf-cfrg-vdaf/poc')

from common import Unsigned, front, vec_add, vec_sub
from flp_generic import FlpGeneric
import hashlib
from typing import Optional, Union
from vdaf import Vdaf, test_vdaf
from vdaf_poplar1 import Poplar1
from vidpf import Vidpf
from xof import XofShake128


# Domain separation: FLP prove randomness
USAGE_PROVE_RAND = 0

# Domain separation: FLP Helper proof share
USAGE_PROOF_SHARE = 1

# Domain separation: FLP query randomness
USAGE_QUERY_RAND = 2


class Mastic(Vdaf):
    # Operational types and parameters.
    Field = None # Set by `with_params()`
    Vidpf = None # Set by `with_params()`
    Flp = None # Set by `with_params()`
    Xof = XofShake128
    ROOT_PROOF = hashlib.sha3_256().digest() # Hash of the empty string

    # Parameters required by `Vdaf`.
    ID: Unsigned = 0xFFFFFFFF
    VERIFY_KEY_SIZE = Xof.SEED_SIZE
    NONCE_SIZE = 16
    RAND_SIZE = None # Set by `with_params()`
    SHARES = 2
    ROUNDS = 1

    # Types required by `Vdaf`
    AggParam = Poplar1.AggParam
    PublicShare = None # TODO(cjpatton)
    InputShare = None # TODO(cjpatton)
    PrepMessage = None

    @classmethod
    def shard(cls, measurement, nonce, rand):
        (vidpf_rand, rand) = front(cls.Vidpf.RAND_SIZE, rand)
        (prove_rand_seed, rand) = front(cls.Xof.SEED_SIZE, rand)
        (helper_seed, rand) = front(cls.Xof.SEED_SIZE, rand)

        (alpha, meas) = measurement
        beta = cls.Flp.encode(meas)

        # Generate VIDPF keys.
        (init_seed, correction_words, cs_proofs) = \
            cls.Vidpf.gen(alpha, beta, nonce, vidpf_rand)
        public_share = (correction_words, cs_proofs)

        # Generate FLP shares.
        prove_rand = cls.Xof.expand_into_vec(cls.Field,
            prove_rand_seed,
            cls.domain_separation_tag(USAGE_PROVE_RAND),
            b'',
            cls.Flp.PROVE_RAND_LEN,
        )

        proof = cls.Flp.prove(beta, prove_rand, [])
        leader_proof_share = vec_sub(proof,
                                     cls.helper_proof_share(helper_seed))

        input_shares = [
            (init_seed[0], leader_proof_share),
            (init_seed[1], helper_seed),
        ]
        return (public_share, input_shares)

    @classmethod
    def is_valid(cls, agg_param, previous_agg_params):
        (level, _prefixes) = agg_param
        if cls.Vidpf.INCREMENTAL_MODE:
            # The first level evaluated must be `0` and all levels must be distinct.
            #
            # TODO(cjpatton) Consider relaxing this check to allow for
            # "fast-start". Rather than start at the first level, we might want
            # to start at a later level and more candidate prefixes. For
            # example, instead of starting at level `0` with all `2`-bit
            # prefixes, we might start at level `7` with all `8`-bit prefixes.
            #
            # The most natural requirement is that we check the FLP the first
            # time we aggregate the batch. However this can't be enforced
            # unless we change the structure of the aggregation parameter.
            # Ideally it's precisely the same as Poplar1 so that we don't have
            # to change things too much at the DAP level.
            #
            # One solution is to make the first level a parameter of the VDAF.
            # This is probably a good idea anyway, since it's a trade-off the
            # Aggregators will probably want to agree on anyway.
            return (
                (len(previous_agg_params) == 0 and level == 0) or \
                previous_agg_params[0][0] == 0
            ) and all(
                level != other_level
                for (other_level, _) in previous_agg_params
            )
        else:
            # Only one level may be evaluated and it must be `BITS - 1`.
            return len(previous_agg_params) == 0 and \
                level == cls.Vidpf.BITS - 1


    @classmethod
    def prep_init(cls, verify_key, agg_id, agg_param,
                  nonce, public_share, input_share):
        (level, prefixes) = agg_param
        (init_seed, proof_share) = cls.expand_input_share(agg_id, input_share)
        (correction_words, cs_proofs) = public_share

        # Ensure that candidate prefixes are all unique and appear in
        # lexicographic order.
        for i in range(1, len(prefixes)):
            if prefixes[i-1] >= prefixes[i]:
                raise ValueError('out of order prefix')

        # Evaluate the VIDPF.
        (out_share, level_proof) = cls.Vidpf.eval(agg_id,
                                                  correction_words,
                                                  init_seed,
                                                  level,
                                                  prefixes,
                                                  cs_proofs,
                                                  cls.ROOT_PROOF,
                                                  nonce)

        # Compute the FLP verifier share, if applicable.
        verifier_share = None
        if cls.do_range_check(agg_param):
            # Evaluate the VIDPF at each child of the root node.
            #
            # One-hot verifiability: it is sufficient to check the proof over
            # the sum of the outputs, since VIDPF VIDPF ensures that exactly
            # one of the children is equal to the encoded `beta` (and the other
            # is equal to `0`).
            #
            # Path verifiability: It is sufficient to check the proof just
            # once, since the path verifiability property of VIDPF ensures that
            # the same `beta` is propagated along the entire `alpha` path.
            #
            # Implementation note: This invocation of the VIDPF is redundant.
            # We evaluate at least one (and likely both) of these prefixes
            # during the main invocation below.
            (out_share, _level0_proof) = cls.Vidpf.eval(agg_id,
                                                        correction_words,
                                                        init_seed,
                                                        0,
                                                        [0, 1],
                                                        cs_proofs,
                                                        cls.ROOT_PROOF,
                                                        nonce)
            meas_share = vec_add(out_share[0], out_share[1])

            query_rand = cls.Xof.expand_into_vec(
                cls.Flp.Field,
                verify_key,
                cls.domain_separation_tag(USAGE_QUERY_RAND),
                nonce, # TODO(cjpatton) Consider binding to the VIDPF mode
                cls.Flp.QUERY_RAND_LEN,
            )

            verifier_share = cls.Flp.query(meas_share,
                                           proof_share,
                                           query_rand,
                                           [], # joint_rand
                                           cls.SHARES)

        prep_state = []
        for val_share in out_share:
            prep_state += cls.Flp.truncate(val_share)
        prep_share = (level_proof, verifier_share)
        return (prep_state, prep_share)

    @classmethod
    def prep_shares_to_prep(cls, agg_param, prep_shares):
        if len(prep_shares) != 2:
            raise ValueError('unexpected number of prep shares')

        # Verify the VIDPF output.
        (level_proof_0, verifier_share_0) = prep_shares[0]
        (level_proof_1, verifier_share_1) = prep_shares[1]
        if level_proof_0 != level_proof_1:
            raise Exception('output vector is not one-hot')

        # Finish verifying the FLP, if applicable.
        if cls.do_range_check(agg_param):
            if verifier_share_0 == None or verifier_share_1 == None:
                raise ValueError('prep share with missing verifier share')

            verifier = vec_add(verifier_share_0, verifier_share_1)
            if not cls.Flp.decide(verifier):
                raise Exception('programmed measurement is not in range')

        return None

    @classmethod
    def prep_next(_cls, prep_state, prep_msg):
        if prep_msg != None:
            raise ValueError('unexpected prep message')
        return prep_state

    @classmethod
    def aggregate(cls, agg_param, out_shares):
        (level, prefixes) = agg_param
        agg_share = cls.Field.zeros(len(prefixes))
        for out_share in out_shares:
            agg_share = vec_add(agg_share, out_share)
        return agg_share

    @classmethod
    def unshard(cls, agg_param,
                agg_shares, _num_measurements):
        (level, prefixes) = agg_param
        agg = cls.Field.zeros(len(prefixes))
        for agg_share in agg_shares:
            agg = vec_add(agg, agg_share)

        agg_result = []
        for chunk_start in range(0, len(agg), cls.Flp.OUTPUT_LEN):
            chunk = agg[chunk_start:chunk_start+cls.Flp.OUTPUT_LEN]
            # We don't know how many measurements correspond to each prefix, so
            # just use `num_measurements == 0` as a dummy value. This means that
            # Mastic is not compatible with all FLPs.
            #
            # TODO(cjpatton) Decide if we should try to make Mastic compatible
            # with all FLPs. We can do so by piggy-packing a counter with each
            # output at the cost of mild communication overhead.
            agg_result.append(cls.Flp.decode(chunk, 0))
        return agg_result

    @classmethod
    def expand_input_share(cls, agg_id, input_share):
        (init_seed, proof_share) = input_share
        if agg_id > 0:
            proof_share = cls.helper_proof_share(proof_share)
        return (init_seed, proof_share)

    @classmethod
    def helper_proof_share(cls, helper_seed):
        return cls.Xof.expand_into_vec(
            cls.Field,
            helper_seed,
            cls.domain_separation_tag(USAGE_PROOF_SHARE),
            b'',
            cls.Flp.PROOF_LEN,
        )

    @classmethod
    def do_range_check(cls, agg_param):
        (level, _prefixes) = agg_param
        return (level == cls.Vidpf.BITS-1 and not cls.Vidpf.INCREMENTAL_MODE) or \
                    level == 0

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
    def with_params(cls, bits, validity_circuit, incremental_mode):
        if validity_circuit.JOINT_RAND_LEN > 0:
            # TODO(cjpatton) Add support for FLPs with joint randomness.
            raise NotImplementedError()

        class MasticWithParams(cls):
            # Operational types and parameters.
            Flp = FlpGeneric(validity_circuit)
            Field = Flp.Field
            Vidpf = Vidpf.with_params(Flp.Field, bits, Flp.MEAS_LEN, incremental_mode)
            # TODO(cjpatton) Add test_vec_name to base spec for the validity
            # circuit so that we can call it here.
            test_vec_name = 'Mastic({}, {}, incremental_mode={})'.format(
                bits, validity_circuit, incremental_mode)

            # Vdaf types and parameters.
            RAND_SIZE = Vidpf.RAND_SIZE + cls.Xof.SEED_SIZE * 2

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


if __name__ == '__main__':
    from flp_generic import Count
    from common import from_be_bytes

    test_vdaf(
        Mastic.with_params(2, Count(), True),
        (0, (0b0, 0b1)),
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
        Mastic.with_params(2, Count(), True),
        (1, (0b00, 0b01)),
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
        Mastic.with_params(16, Count(), True),
        (14, (0b111100001111000,)),
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
        Mastic.with_params(256, Count(), True),
        (
            63,
            (
                from_be_bytes(b'00000000'),
                from_be_bytes(b'01234567'),
            ),
        ),
        [
            (from_be_bytes(b'0123456789abcdef0123456789abcdef'), 1),
            (from_be_bytes(b'01234567890000000000000000000000'), 1),
        ],
        [0, 2],
    )

    # TODO(cjpatton) Add tests for a circuit with `MEAS_LEN > 1` so that we can
    # assess whether any `Vidpf` encode assumes `len(beta) == 1`.

    # TODO(cjpatton) `is_valid()` tests.
