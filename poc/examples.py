'''Examples of Mastic use cases.'''

import hashlib
import math

from vdaf_poc.common import gen_rand
from vdaf_poc.field import Field64, Field128
from vdaf_poc.flp_bbcggi19 import Count, Histogram, Sum
from vdaf_poc.vdaf_poplar1 import Poplar1
from vdaf_poc.vdaf_prio3 import Prio3Histogram

from mastic import Mastic


def get_reports_from_measurements(mastic, ctx, measurements):
    reports = []
    for measurement in measurements:
        nonce = gen_rand(16)
        rand = gen_rand(mastic.RAND_SIZE)
        (public_share, input_shares) = mastic.shard(ctx,
                                                    measurement,
                                                    nonce,
                                                    rand)
        reports.append((nonce, public_share, input_shares))
    return reports


def get_threshold(thresholds, prefix):
    '''
    Return the threshold of the given prefix if it exists. If not, check if any
    of its prefixes exist. If not, return the default threshold.
    '''
    for level in reversed(range(len(prefix)-1)):
        if prefix[:level+1] in thresholds:
            return thresholds[prefix[:level+1]]
    return thresholds['default']  # Return the default threshold


def compute_heavy_hitters(mastic, ctx, thresholds, reports):
    verify_key = gen_rand(16)

    prefixes = [(False,), (True,)]
    prev_agg_params = []
    heavy_hitters = []
    for level in range(mastic.vidpf.BITS):
        agg_param = (level, prefixes, level == 0)
        assert mastic.is_valid(agg_param, prev_agg_params)

        # Aggregators prepare reports for aggregation.
        agg_shares = [mastic.agg_init(agg_param) for _ in range(mastic.SHARES)]

        print('agg_shares', agg_shares)

        for (nonce, public_share, input_shares) in reports:
            # Each aggregator broadcast its prep share.
            (prep_state, prep_shares) = zip(*[
                mastic.prep_init(
                    verify_key,
                    ctx,
                    agg_id,
                    agg_param,
                    nonce,
                    public_share,
                    input_shares[agg_id]) for agg_id in range(mastic.SHARES)
            ])

            # Each aggregator computes the prep message.
            prep_msg = mastic.prep_shares_to_prep(ctx, agg_param, prep_shares)

            # Each Aggregator computes and aggregates its output share.
            for agg_id in range(mastic.SHARES):
                out_share = mastic.prep_next(ctx, prep_state[agg_id], prep_msg)
                assert not isinstance(out_share, tuple)
                agg_shares[agg_id] = mastic.agg_update(agg_param,
                                                       agg_shares[agg_id],
                                                       out_share)

        # Collector computes the aggregate result.
        agg_result = mastic.unshard(agg_param, agg_shares, len(reports))
        prev_agg_params.append(agg_param)

        if level < mastic.vidpf.BITS - 1:
            # Compute the next set of candidate prefixes.
            next_prefixes = []
            for (prefix, count) in zip(prefixes, agg_result):
                threshold = get_threshold(thresholds, prefix)
                if count >= threshold:
                    next_prefixes.append(prefix + (False,))
                    next_prefixes.append(prefix + (True,))
            prefixes = next_prefixes
        else:
            for (prefix, count) in zip(prefixes, agg_result):
                threshold = get_threshold(thresholds, prefix)
                if count >= threshold:
                    heavy_hitters.append(prefix)
    return heavy_hitters


def example_weighted_heavy_hitters_mode():
    bits = 4
    ctx = b'example_weighted_heavy_hitters_mode'
    mastic = Mastic(bits, Count(Field64))

    # Clients shard their measurements. Each measurement is comprised of
    # `(alpha, beta)` where `alpha` is the payload string and `beta` is its
    # weight. Here the weight is simply a counter (either `0` or `1`).
    measurements = [
        (mastic.vidpf.test_index_from_int(0b1001, bits), 1),
        (mastic.vidpf.test_index_from_int(0b0000, bits), 1),
        (mastic.vidpf.test_index_from_int(0b0000, bits), 0),
        (mastic.vidpf.test_index_from_int(0b0000, bits), 1),
        (mastic.vidpf.test_index_from_int(0b1001, bits), 1),
        (mastic.vidpf.test_index_from_int(0b0000, bits), 1),
        (mastic.vidpf.test_index_from_int(0b1100, bits), 1),
        (mastic.vidpf.test_index_from_int(0b0011, bits), 1),
        (mastic.vidpf.test_index_from_int(0b1111, bits), 0),
        (mastic.vidpf.test_index_from_int(0b1111, bits), 0),
        (mastic.vidpf.test_index_from_int(0b1111, bits), 1),
    ]

    reports = get_reports_from_measurements(mastic, ctx, measurements)

    thresholds = {
        'default': 2,
    }

    # Collector and Aggregators compute the weighted heavy hitters.
    heavy_hitters = compute_heavy_hitters(mastic, ctx, thresholds, reports)
    print("Weighted heavy-hitters:", heavy_hitters)
    assert heavy_hitters == [mastic.vidpf.test_index_from_int(0b0000, bits),
                             mastic.vidpf.test_index_from_int(0b1001, bits)]


def example_weighted_heavy_hitters_mode_with_different_thresholds():
    bits = 4
    ctx = b'example_weighted_heavy_hitters_mode_with_different_thresholds'
    mastic = Mastic(bits, Count(Field64))

    # Clients shard their measurements. Each measurement is comprised of
    # `(alpha, beta)` where `alpha` is the payload string and `beta` is its
    # weight. Here the weight is simply a counter (either `0` or `1`).
    measurements = [
        (mastic.vidpf.test_index_from_int(0b0000, bits), 1),
        (mastic.vidpf.test_index_from_int(0b0001, bits), 1),
        (mastic.vidpf.test_index_from_int(0b1001, bits), 1),
        (mastic.vidpf.test_index_from_int(0b1001, bits), 1),
        (mastic.vidpf.test_index_from_int(0b1010, bits), 1),
        (mastic.vidpf.test_index_from_int(0b1010, bits), 1),
        (mastic.vidpf.test_index_from_int(0b1111, bits), 1),
        (mastic.vidpf.test_index_from_int(0b1111, bits), 1),
        (mastic.vidpf.test_index_from_int(0b1111, bits), 1),
        (mastic.vidpf.test_index_from_int(0b1111, bits), 1),
        (mastic.vidpf.test_index_from_int(0b1111, bits), 1),
    ]

    reports = get_reports_from_measurements(mastic, ctx, measurements)

    # (prefix, level): threshold
    # Note that levels start from zero
    thresholds = {
        'default': 2,
        mastic.vidpf.test_index_from_int(0b00, 2): 1,
        mastic.vidpf.test_index_from_int(0b10, 2): 3,
        mastic.vidpf.test_index_from_int(0b11, 2): 5,
    }

    # Collector and Aggregators compute the weighted heavy hitters.
    heavy_hitters = compute_heavy_hitters(mastic, ctx, thresholds, reports)
    print("Weighted heavy-hitters with different thresholds:", heavy_hitters)
    assert heavy_hitters == [
        mastic.vidpf.test_index_from_int(0b0000, bits),
        mastic.vidpf.test_index_from_int(0b0001, bits),
        mastic.vidpf.test_index_from_int(0b1111, bits),
    ]


def example_attribute_based_metrics_mode():
    bits = 8
    ctx = b'example_attribute_based_metrics_mode'
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
        return mastic.vidpf.test_index_from_int(sha3.digest()[0], bits)

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
            ctx,
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
    agg_shares = [mastic.agg_init(agg_param) for _ in range(mastic.SHARES)]
    for (nonce, public_share, input_shares) in reports:
        # Each aggregator broadcast its prep share.
        (prep_state, prep_shares) = zip(*[
            mastic.prep_init(
                verify_key,
                ctx,
                agg_id,
                agg_param,
                nonce,
                public_share,
                input_shares[agg_id]) for agg_id in range(mastic.SHARES)
        ])

        # Each aggregator computes the prep message.
        prep_msg = mastic.prep_shares_to_prep(ctx, agg_param, prep_shares)

        # Each Aggregator computes and aggregates its output share.
        for agg_id in range(mastic.SHARES):
            out_share = mastic.prep_next(ctx, prep_state[agg_id], prep_msg)
            assert not isinstance(out_share, tuple)
            agg_shares[agg_id] = mastic.agg_update(agg_param,
                                                   agg_shares[agg_id],
                                                   out_share)

    # Collector computes the aggregate result.
    agg_result = mastic.unshard(agg_param, agg_shares, len(measurements))
    print('Election results:', list(zip(attrs, agg_result)))
    assert agg_result == [6, 0, 4]


def example_poplar1_overhead():
    nonce = gen_rand(16)

    cls = Poplar1(256)
    (public_share, input_shares) = cls.shard(b'poplar',
                                             (False,)*256,
                                             nonce,
                                             gen_rand(cls.RAND_SIZE))
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
    (public_share, input_shares) = cls.shard(b'mastic_count',
                                             ((False,)*256, 0),
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
    (public_share, input_shares) = cls.shard(b'mastic_sum_8',
                                             ((False,)*256, 0),
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
    (public_share, input_shares) = cls.shard(b'mastic_histogram_100',
                                             ((False,)*32, 0),
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
    (public_share, input_shares) = cls.shard(b'prio3_histogram',
                                             0,
                                             nonce,
                                             gen_rand(cls.RAND_SIZE))
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


if __name__ == '__main__':
    example_weighted_heavy_hitters_mode()
    example_attribute_based_metrics_mode()
    example_weighted_heavy_hitters_mode_with_different_thresholds()
    example_poplar1_overhead()
