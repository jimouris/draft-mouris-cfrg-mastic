"""Verifiable Distributed Point Function (VDPF)"""

from common import \
    ERR_INPUT, \
    Bytes, \
    format_dst, \
    gen_rand, \
    vec_add, \
    vec_sub, \
    xor
import hashlib
import ring
from prg import PrgFixedKeyAes128

class Vdpf:
    """A Verifiable Distributed Point Function (VDPF)."""

    # Number of keys generated by the vdpf-key generation algorithm.
    SHARES = 2

    # Bit length of valid input values (i.e., the length of `alpha` in bits).
    BITS = 16

    # The length of each output vector (i.e., the length of `beta_leaf`).
    VALUE_LEN = 2

    # Size in bytes of each vdpf key share.
    KEY_SIZE = PrgFixedKeyAes128.SEED_SIZE

    # Number of random bytes consumed by the `gen()` algorithm.
    RAND_SIZE = 2 * PrgFixedKeyAes128.SEED_SIZE

    # A nonce.
    BINDER = b'some nonce'

    # The ring used to represent the leaf nodes of the vdpf tree.
    RING = ring.Ring(2^16)

    # The ring for the control bits.
    R2 = ring.Ring(2)

    @classmethod
    def node_expand(cls, seed, ctrl, cor_word):
        '''
        extend and correct
        https://eprint.iacr.org/2021/580.pdf Algorithm 1
        '''
        c_s, ctrl_left, ctrl_right = cor_word

        ((s_left, s_right), (t_left, t_right)) = cls.extend(seed)

        s_0 = correct(s_left, c_s, ctrl)
        t_0 = correct(t_left, ctrl_left, ctrl)

        s_1 = correct(s_right, c_s, ctrl)
        t_1 = correct(t_right, ctrl_right, ctrl)

        return ((s_0, t_0), (s_1, t_1))

    @classmethod
    def cw_gen(cls, input_bit, seed, ctrl):
        '''
        https://eprint.iacr.org/2021/580.pdf Algorithm 2
        '''
        (s_0, t_0) = cls.extend(seed[0]) # s_0^L || s_0^R || t_0^L || t_0^R
        (s_1, t_1) = cls.extend(seed[1]) # s_1^L || s_1^R || t_1^L || t_1^R

        diff, same = (1, 0) if input_bit else (0, 1) # if x = 0 then Diff <- L, Same <- R

        s_c = xor(s_0[same], s_1[same])
        t_c = (
            t_0[0] + t_1[0] + cls.R2.one() + cls.R2.new_elm(input_bit), # t_c^L
            t_0[1] + t_1[1] + cls.R2.new_elm(input_bit),                # t_c^R
        )
        cor_word = (s_c, t_c[0], t_c[1]) # s_c || t_c^L || t_c^R

        new_s = (
            correct(s_0[diff], s_c, ctrl[0]), # s0'
            correct(s_1[diff], s_c, ctrl[1]), # s1'
        )
        new_t = (
            correct(t_0[diff], t_c[diff], ctrl[0]), # t0'
            correct(t_1[diff], t_c[diff], ctrl[1]), # t1'
        )
        return cor_word, new_s, new_t

    @classmethod
    def gen(cls, alpha, beta, rand):
        '''
        https://eprint.iacr.org/2021/580.pdf Fig. 1
        '''
        if alpha >= 2^cls.BITS:
            raise ERR_INPUT # alpha too long
        if len(rand) != cls.RAND_SIZE:
            raise ERR_INPUT # unexpected length for random input

        init_seed = [
            rand[:PrgFixedKeyAes128.SEED_SIZE],
            rand[PrgFixedKeyAes128.SEED_SIZE:],
        ]

        # s0^0, s1^0, t0^0, t1^0
        seed = init_seed.copy()
        ctrl = [cls.R2.zero(), cls.R2.one()]
        correction_words = []
        for i in range(cls.BITS):
            alpha_i = (alpha >> (cls.BITS - i - 1)) & 1
            cor_word, seed, ctrl = cls.cw_gen(alpha_i, seed, ctrl)
            correction_words.append(cor_word)
        seed_n = seed
        t_n = ctrl

        sha256 = hashlib.sha256()
        sha256.update(str(alpha).encode('ascii') + seed_n[0])
        proof_0 = sha256.digest()

        sha256 = hashlib.sha256()
        sha256.update(str(alpha).encode('ascii') + seed_n[1])
        proof_1 = sha256.digest()

        cor_seed = xor(proof_0, proof_1)

        seed_last = seed_n
        t_last = t_n
        if t_last[0] == t_last[1]:
            raise ValueError('ERROR, go to 1')

        _, convert_0 = cls.convert(seed_last[0])
        _, convert_1 = cls.convert(seed_last[1])
        out_cor_word = vec_add(vec_sub(beta, convert_0), convert_1)
        mask = cls.RING.one() - \
            cls.RING.new_elm(2) * cls.RING.new_elm(ctrl[1].as_unsigned())
        for i in range(len(out_cor_word)):
            out_cor_word[i] *= mask

        return (init_seed, correction_words, cor_seed, out_cor_word)

    @classmethod
    def batch_verifiable_eval(cls, agg_id, init_seed, cor_words,
                              cor_seed, out_cor_word, eval_points):
        '''
        Verifiable evaluation algorithm BVEval for batch verifiable evaluation.
        '''
        y_vec = []
        proof = cor_seed

        # for l in range(eval_points):
        for x_l in eval_points:
            seed = init_seed
            ctrl = cls.R2.new_elm(agg_id)

            for i in range(cls.BITS):
                (s_0, t_0), (s_1, t_1) = cls.node_expand(seed, ctrl, 
                                                         cor_words[i])

                # b_1...b_n = msb(x_l)...lsb(x_l)
                b_i = (x_l >> (cls.BITS - i - 1)) & 1
                seed, ctrl = (s_0, t_0) if b_i == 0 else (s_1, t_1)

            # proof_prime = hash(x_l | s)
            sha256 = hashlib.sha256()
            sha256.update(str(x_l).encode('ascii') + seed)
            proof_prime = sha256.digest()

            _, y_l = cls.convert(seed)
            y_l = correct(y_l, out_cor_word, 
                          cls.RING.new_elm(ctrl.as_unsigned()))

            mask = cls.RING.one() - \
                cls.RING.new_elm(2) * cls.RING.new_elm(agg_id)
            for i in range(len(y_l)):
                y_l[i] *= mask
            y_vec.append(y_l)

            sha256 = hashlib.sha256()
            sha256.update(
                xor(
                    proof,
                    correct(proof_prime,cor_seed,
                            cls.RING.new_elm(ctrl.as_unsigned()))
                )
            )
            proof = xor(proof, sha256.digest())

        return (y_vec, proof)

    @classmethod
    def verify(cls, proof_0, proof_1):
        '''Check proofs'''
        return proof_0 == proof_1

    @classmethod
    def extend(cls, seed):
        '''
        Extend seed to (seed_L, t_L, seed_R, t_R)
        '''
        prg = PrgFixedKeyAes128(seed, format_dst(1, 0, 0), cls.BINDER)
        new_seed = [
            prg.next(PrgFixedKeyAes128.SEED_SIZE),
            prg.next(PrgFixedKeyAes128.SEED_SIZE),
        ]
        bit = prg.next(1)[0]
        ctrl = [cls.R2.new_elm(bit & 1), cls.R2.new_elm((bit >> 1) & 1)]
        return (new_seed, ctrl)

    @classmethod
    def convert(cls, seed):
        '''
        Converting seed to a pseudorandom element of G.
        '''
        prg = PrgFixedKeyAes128(seed, format_dst(1, 0, 1), cls.BINDER)
        next_seed = prg.next(PrgFixedKeyAes128.SEED_SIZE)
        return (next_seed, prg.next_vec_ring(cls.RING, cls.VALUE_LEN))


def correct(k_0, k_1, ctrl):
    ''' return k_0 if ctrl == 0 else xor(k_0, k_1) '''
    if isinstance(k_0, Bytes):
        return xor(k_0, ctrl.conditional_select(k_1))
    if isinstance(k_0, list): # list of ints or ring elements
        for i in range(len(k_0)):
            k_0[i] += ctrl * k_1[i]
        return k_0
    # int or ring element
    return k_0 + ctrl * k_1


def main():
    '''Driver'''

    vdpf = Vdpf
    vdpf.VALUE_LEN = 1
    vdpf.BITS = 2
    vdpf.RING = ring.Ring(2^16)
    vdpf.BINDER = b'some nonce'

    beta = [vdpf.RING.one()] * vdpf.VALUE_LEN
    eval_points = list(range(2 ^ vdpf.BITS)) # [0b00, 0b01, 0b10, 0b11, ...]
    rand = gen_rand(vdpf.RAND_SIZE)

    init_seed, cor_words, cor_seed, out_cor_word = vdpf.gen(0b11, beta, rand)

    out = [vdpf.RING.zeros(vdpf.VALUE_LEN)] * len(eval_points)
    proofs = []
    for agg_id in range(vdpf.SHARES):
        y_agg_id, proof_agg_id = vdpf.batch_verifiable_eval(
            agg_id, init_seed[agg_id], cor_words, 
            cor_seed, out_cor_word, eval_points
        )
        proofs.append(proof_agg_id)
        for i in range(len(eval_points)):
            out[i] = vec_add(out[i], y_agg_id[i])

    print(out)
    assert vdpf.verify(proofs[0], proofs[1])


if __name__ == '__main__':
    main()
