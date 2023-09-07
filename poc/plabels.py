import sys
sys.path.append('draft-irtf-cfrg-vdaf/poc')

from typing import Tuple, Union
from common import \
    ERR_INPUT, \
    Bytes, \
    format_dst, \
    gen_rand, \
    vec_add, \
    vec_sub, \
    vec_neg, \
    xor
import hashlib
import prg
import vidpf
import flp

USAGE_PLASMA_H1 = 1
USAGE_PLASMA_H2 = 2
USAGE_JOINT_RAND = 3
USAGE_QUERY_RAND = 4
USAGE_PROVE_RAND = 5
USAGE_PROOF_SHARE = 6


class Plabels(Vdaf):
    """A VDAF."""
    Vidpf = vidpf.Vidpf
    Flp = flp.Flp
    Field = Flp.Field
    Prg = prg.Prg
    Hash = hashlib.sha3_256

     # Parameters required by `Vdaf`.
    ID: Unsigned = 0x10000000
    VERIFY_KEY_SIZE = None  # Set by Vidpf
    NONCE_SIZE = None  # WIP
    RAND_SIZE = None  # Set by Vidpf
    SHARES = 2
    ROUNDS = 1

    # Types
    Measurement = None
    AggParam = None
    # The state of an aggregator during the Prepare computation.
    Prep = None
    # The output share type.
    OutShare = None
    # The aggregate result type.
    AggResult = None

    @classmethod
    def measurement_to_input_shares(Plabels,
                                    measurement: Measurement,
                                    nonce: Bytes["Vdaf.NONCE_SIZE"],
                                    rand: Bytes["Vdaf.RAND_SIZE"],
                                    ) -> tuple[Bytes,  #public share; joint_r
                                               Vec[Bytes]]: #input shares
        """
        Shard a measurement into a "public share" and a sequence of input
        shares, one for each Aggregator. This method is run by the Client.
        """
        vidpf_rand, rand = front(Vidpf.RAND_SIZE, rand)
        
        ### WIP generate joint randomness & hints
        ### Specifically the WIP is that I'm not bothering with
        ### blinds and jr hints yet
        helper_seed, rand = front(Prg.SEED_SIZE, rand)
        prove_rand_seed, rand = front(Prg.SEED_SIZE, rand)
        joint_rand_seed, rand = front(Prg.SEED_SIZE, rand)
        if len(rand)!=0:
            raise ERR_INPUT  # unexpected length for random input

        joint_rand = Plabels.Prg.expand_into_vec(Plabels.Field,
                joint_rand_seed,
                Plabels.domain_separation_tag(USAGE_JOINT_RAND), byte(0),
                Plabels.Flp.JOINT_RAND_LEN,
        )
        prove_rand = Prg.expand_into_vec(Plabels.Field,
                prove_rand_seed,
                Plabels.domain_separation_tag(USAGE_PROVE_RAND), byte(0),
                Plabels.Flp.PROVE_RAND_LEN,
        )
        
        # generate VIDPF keys
        alpha, val = measurement
        beta = (val) * Plabels.Vidpf.BITS 
        init_seed, correction_words, cs_proofs = \
                       Plabels.Vidpf.gen(alpha, beta, vidpf_rand)
        public_share = (correction_words, cs_proofs, joint_rand_seed)

        # generate FLP
        encoded_meas = Plabels.Flp.encode(val)
        proof = Plabels.Flp.prove(val, prove_rand, joint_rand)
        leader_proof_share = proof - Plabels.Prg.expand_into_vec(Plabels.Field,
                helper_seed,
                Plabels.domain_separation_tag(USAGE_PROOF_SHARE), byte(0),
                Plabels.Flp.PROOF_LEN,
            )
        
        input_shares = ((init_seed[0], leader_proof_share),
                        (init_seed[1], helper_seed))
        return (public_share, input_shares)

    @classmethod
    def is_valid(Vdaf, agg_param: AggParam,
                 previous_agg_params: set[AggParam]) -> Bool:
        """
        Check if `agg_param` is valid for use with an input share that has
        previously been used with all `previous_agg_params`.
        """
        (level, prefixes) = agg_param
        z = all(len(p) == level-1 for p in prefixes)
        return z and all(
            level != other_level
            for (other_level, _) in previous_agg_params
        )
        
    @classmethod
    def prep_init(Plabels,
                  verify_key: Bytes,
                  agg_id: Unsigned,
                  agg_param: AggParam,
                  nonce: Bytes,
                  public_share: Bytes,
                  input_share: Bytes) -> Prep:
        """
        Initialize the Prepare state for the given input share. This method is
        run by an Aggregator. Along with the the public share and its input
        share, the inputs include the verification key shared by all of the
        Aggregators, the Aggregator's ID (a unique integer in range `[0,
        SHARES)`, and the aggregation parameter and nonce agreed upon by all of
        the Aggregators.
        """
        hash = Plabels.Hash()
        
        (level, prefixes) = agg_param
        (init_seed, proof_share) = input_share
        (correction_words, cs_proofs, joint_rand_seed) = public_share

        # Ensure that candidate prefixes are all unique and appear in
        # lexicographic order.
        for i in range(1, len(prefixes)):
            if prefixes[i-1] >= prefixes[i]:
                raise ERR_INPUT  # out-of-order prefix

        # Expand the set of prefixes to the next level
        prefixes_with_zero = [2*p for p in prefixes]
        prefixes_with_one = [p+1 for p in prefixes_with_zero]

        # Evaluate the VIDPF at the given set of prefixes.
        (out_share, pi_proof) = Plabels.Vidpf.eval(agg_id,
                                                   correction_words,
                                                   init_seed,
                                                   level-1,
                                                   prefixes,
                                                   cs_proofs)
        # Evaluate the VIDPF at all children of the given set of prefixes
        (out_share_zeroes, pi_proof_zero) = Plabels.Vidpf.eval(agg_id,
                                                   correction_words,
                                                   init_seed,
                                                   level,
                                                   prefixes_with_zero,
                                                   cs_proofs)
        (out_share_ones, pi_proof_one) = Plabels.Vidpf.eval(agg_id,
                                                   correction_words,
                                                   init_seed,
                                                   level,
                                                   prefixes_with_one,
                                                   cs_proofs)
        
        # If level = 0 then we validate the output using the FLP. 
        if level == 0:
            query_rand = Plabels.Prg.expand_into_vec(
                Plabels.Flp.Field,
                verify_key,
                Plabels.domain_separation_tag(USAGE_QUERY_RAND),
                nonce,
                Plabels.Flp.QUERY_RAND_LEN,
            )
            joint_rand = Plabels.Prg.expand_into_vec(Plabels.Flp.Field,
                joint_rand_seed,
                Plabels.domain_separation_tag(USAGE_JOINT_RAND), byte(0),
                Plabels.Flp.JOINT_RAND_LEN,
            )
            if agg_id != 0:  # expand helper share from seed
                proof_share = Plabels.Prg.expand_into_vec(Plabels.Field,
                proof_share,
                Plabels.domain_separation_tag(USAGE_PROOF_SHARE), byte(0),
                Plabels.Flp.PROOF_LEN,
            )

            verifier_share = Plabels.Flp.query(out_share[0],
                                               proof_share,
                                               query_rand,
                                               joint_rand,
                                               Plabels.SHARES)

            prep_msg = verifier_share
        
        # Otherwise we validate that each node's value equals the sum of its
        # children's values. 
        else:
            for i in range(len(prefixes)):
                hash.update(prefixes[i])
                local_hash = Plabels.Hash()
                local_hash.update(prefixes[i])
                if agg_id == 0:
                    local_hash.update(out_share[i] \
                                - out_share_zeroes[i] \
                                - out_share_ones[i])
                else:
                    local_hash.update(-out_share[i] \
                                + out_share_zeroes[i] \
                                + out_share_ones[i])
                h = Plabels.Prg.derive_seed(verify_key, 
                            Plabels.domain_separation_tag(USAGE_PLASMA_H1),
                            local_hash.digest())
                hash.update(local_hash.digest())
                hash.update(pi_proof_zero[i])
                hash.update(pi_proof_one[i])

            prep_msg = Plabels.Prg.derive_seed(verify_key, 
                            Plabels.domain_separation_tag(USAGE_PLASMA_H2),
                            hash.digest())

        return (out_share, prep_msg)

    @classmethod
    def prep_next(Plabels,
                  prep: Prep,
                  inbound: Optional[Bytes],
                  ) -> Union[Tuple[Prep, Bytes], Plabels.OutShare]:
        """
        Consume the inbound message from the previous round (or `None` if this
        is the first round) and return the aggregator's share of the next round
        (or the aggregator's output share if this is the last round).
        """
        (out_share, prep_msg) = prep

        if inbound is None:
            return (prep, prep_msg)
        
        return out_share
        


    @classmethod
    def prep_shares_to_prep(Plabels,
                            agg_param: AggParam,
                            prep_shares: Vec[Bytes]) -> Bytes:
        """
        Unshard the Prepare message shares from the previous round of the
        Prapare computation. This is called by an aggregator after receiving all
        of the message shares from the previous round. The output is passed to
        Prep.next().
        """

        (level, prefixes) = agg_param
        if level == 0:
            verifier = Plabels.Flp.Field.zeros(Plabels.Flp.VERIFIER_LEN)
            for verifier_share in prep_shares:
                verifier = vec_add(verifier, verifier_share)

            if not Plabels.Flp.decide(verifier):
                raise ERR_VERIFY  # FLP check failed
        else: 
            if prep_shares[0] != prep_shares[1]:
                raise ERR_VERIFY # PLASMA validity check failed
        return b''

    @classmethod
    def out_shares_to_agg_share(Plabels,
                                agg_param: AggParam,
                                out_shares: Vec[OutShare]) -> Bytes:
        """
        Merge a list of output shares into an aggregate share, encoded as a byte
        string. This is called by an aggregator after recovering a batch of
        output shares.
        """
        (_, prefixes) = agg_param
        agg_share = Plabels.Field.zeros(len(prefixes))
        for out_share in out_shares:
            agg_share = vec_add(agg_share, out_share)
        return Plabels.Field.encode_vec(agg_share)

    @classmethod
    def agg_shares_to_result(Plabels,
                             agg_param: AggParam,
                             agg_shares: Vec[Bytes],
                             num_measurements: Unsigned) -> AggResult:
        """
        Unshard the aggregate shares (encoded as byte strings) and compute the
        aggregate result. This is called by the Collector.
        """
        (_, prefixes) = agg_param
        agg = Plabels.Field.zeros(len(prefixes))
        for agg_share in agg_shares:
            agg = vec_add(agg, Plabels.Field.decode_vec(agg_share))
        return list(map(lambda x: x.as_unsigned(), agg))


    @classmethod
    def domain_separation_tag(Vdaf, usage: Unsigned) -> Bytes:
        """
        Format domain separation tag for this VDAF with the given usage.
        """
        return format_dst(0, Vdaf.ID, usage)

    @classmethod
    def test_vec_set_type_param(Vdaf, test_vec):
        """
        Add any parameters to `test_vec` that are required to construct this
        class. Return the key that was set or `None` if `test_vec` was not
        modified.
        """
        return None