#!/usr/bin/env python3

import os

from vdaf_poc.test_utils import gen_test_vec_for_vdaf

from mastic import (F, Mastic, MasticAggParam, MasticCount, MasticHistogram,
                    MasticMultihotCountVec, MasticSum, MasticSumVec, W)

# # The path where test vectors are generated.
TEST_VECTOR_PATH = os.environ.get('TEST_VECTOR_PATH', '../test_vec/')


def gen_test_vec_for_mastic(
        test_vec_path: str,
        mastic: Mastic,
        agg_param: MasticAggParam,
        ctx: bytes,
        measurements: list[tuple[tuple[bool, ...], W]],
        test_vec_instance: int,
        print_test_vec: bool = True) -> list[F]:
    return gen_test_vec_for_vdaf(test_vec_path, mastic, agg_param, ctx, measurements, test_vec_instance, print_test_vec)


if __name__ == '__main__':
    context = b'some application'
    vdaf_test_vec_path = TEST_VECTOR_PATH + "/mastic/"

    # Count Test Vectors
    mastic_count = MasticCount(2)
    gen_test_vec_for_mastic(
        vdaf_test_vec_path,
        mastic_count,
        (
            0,
            (
                mastic_count.vidpf.test_index_from_int(0b0, 1),
                mastic_count.vidpf.test_index_from_int(0b1, 1),
            ),
            True,
        ),
        context,
        measurements=[(mastic_count.vidpf.test_index_from_int(0b10, 2), True)],
        test_vec_instance=0,
    )

    gen_test_vec_for_mastic(
        vdaf_test_vec_path,
        mastic_count,
        (
            1,
            (
                mastic_count.vidpf.test_index_from_int(0b00, 2),
                mastic_count.vidpf.test_index_from_int(0b01, 2)
            ),
            True,
        ),
        context,
        measurements=[(mastic_count.vidpf.test_index_from_int(0b10, 2), True)],
        test_vec_instance=1,
    )

    # Sum Test Vectors
    mastic_sum = MasticSum(2, 2**3 - 1)
    gen_test_vec_for_mastic(
        vdaf_test_vec_path,
        mastic_sum,
        (
            0,
            (
                mastic_sum.vidpf.test_index_from_int(0b0, 1),
                mastic_sum.vidpf.test_index_from_int(0b1, 1)
            ),
            True,
        ),
        context,
        measurements=[
            (mastic_sum.vidpf.test_index_from_int(0b10, 2), 1),
            (mastic_sum.vidpf.test_index_from_int(0b00, 2), 6),
            (mastic_sum.vidpf.test_index_from_int(0b11, 2), 7),
            (mastic_sum.vidpf.test_index_from_int(0b01, 2), 5),
            (mastic_sum.vidpf.test_index_from_int(0b11, 2), 2)
        ],
        test_vec_instance=0,
    )

    mastic_sum = MasticSum(2, 2**2 - 1)
    gen_test_vec_for_mastic(
        vdaf_test_vec_path,
        mastic_sum,
        (
            1,
            (
                mastic_sum.vidpf.test_index_from_int(0b00, 2),
                mastic_sum.vidpf.test_index_from_int(0b01, 2)
            ),
            True,
        ),
        context,
        measurements=[
            (mastic_sum.vidpf.test_index_from_int(0b10, 2), 3),
            (mastic_sum.vidpf.test_index_from_int(0b00, 2), 2),
            (mastic_sum.vidpf.test_index_from_int(0b11, 2), 0),
            (mastic_sum.vidpf.test_index_from_int(0b01, 2), 1),
            (mastic_sum.vidpf.test_index_from_int(0b01, 2), 2)
        ],
        test_vec_instance=1,
    )

    # SumVec Test Vectors
    mastic_sum_vec = MasticSumVec(16, 3, 1, 1)
    gen_test_vec_for_mastic(
        vdaf_test_vec_path,
        mastic_sum_vec,
        (
            14,
            (mastic_sum_vec.vidpf.test_index_from_int(0b111100001111000, 15),),
            True
        ),
        context,
        measurements=[
            (
                mastic_sum_vec.vidpf.test_index_from_int(
                    0b1111000011110000, 16
                ),
                [0, 0, 1]
            ),
            (
                mastic_sum_vec.vidpf.test_index_from_int(
                    0b1111000011110001, 16
                ),
                [0, 1, 0]
            )
        ],
        test_vec_instance=0,
    )

    # Histogram Test Vectors
    mastic_histogram = MasticHistogram(2, 4, 2)
    gen_test_vec_for_mastic(
        vdaf_test_vec_path,
        mastic_histogram,
        (
            1,
            (
                mastic_histogram.vidpf.test_index_from_int(0b00, 2),
                mastic_histogram.vidpf.test_index_from_int(0b01, 2)
            ),
            True,
        ),
        context,
        measurements=[
            (mastic_histogram.vidpf.test_index_from_int(0b10, 2), 1),
            (mastic_histogram.vidpf.test_index_from_int(0b01, 2), 2),
            (mastic_histogram.vidpf.test_index_from_int(0b00, 2), 3)
        ],
        test_vec_instance=0,
    )

    # Histogram Test Vectors
    mastic_multi_hot = MasticMultihotCountVec(2, 4, 2, 2)
    gen_test_vec_for_mastic(
        vdaf_test_vec_path,
        mastic_multi_hot,
        (
            1,
            (
                mastic_multi_hot.vidpf.test_index_from_int(0b00, 2),
                mastic_multi_hot.vidpf.test_index_from_int(0b01, 2)
            ),
            True,
        ),
        context,
        measurements=[
            (mastic_multi_hot.vidpf.test_index_from_int(
                0b10, 2), [False, True, True, False]),
            (mastic_multi_hot.vidpf.test_index_from_int(
                0b01, 2), [False, True, True, False])
        ],
        test_vec_instance=0,
    )
