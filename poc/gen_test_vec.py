#!/usr/bin/env python3

import os

from vdaf_poc.field import Field64
from vdaf_poc.flp_bbcggi19 import Count, Sum
from vdaf_poc.test_utils import gen_test_vec_for_vdaf

from mastic import Mastic

# # The path where test vectors are generated.
TEST_VECTOR_PATH = os.environ.get('TEST_VECTOR_PATH', '../test_vec/')


if __name__ == '__main__':

    ctx = b'some application'
    vdaf_test_vec_path = TEST_VECTOR_PATH + "/mastic/"

    # Count Test Vectors
    # Test Vector 0
    mastic = Mastic(2, Count(Field64))
    agg_param = (
        0,
        (
            mastic.vidpf.test_index_from_int(0b0, 1),
            mastic.vidpf.test_index_from_int(0b1, 1),
        ),
        True,
    )
    gen_test_vec_for_vdaf(
        vdaf_test_vec_path,
        mastic,
        agg_param,
        ctx,
        measurements=[(mastic.vidpf.test_index_from_int(0b10, 2), 1)],
        test_vec_instance=0,
    )

    # Test Vector 1
    agg_param = (
        1,
        (
            mastic.vidpf.test_index_from_int(0b00, 2),
            mastic.vidpf.test_index_from_int(0b01, 2)
        ),
        True,
    )
    gen_test_vec_for_vdaf(
        vdaf_test_vec_path,
        mastic,
        agg_param,
        ctx,
        measurements=[(mastic.vidpf.test_index_from_int(0b10, 2), 1)],
        test_vec_instance=1,
    )

    # Sum Test Vectors
    # Test Vector 2
    mastic = Mastic(2, Sum(Field64, 2**3 - 1))
    agg_param = (
        0,
        (
            mastic.vidpf.test_index_from_int(0b0, 1),
            mastic.vidpf.test_index_from_int(0b1, 1)
        ),
        True,
    )
    measurements = [
        (mastic.vidpf.test_index_from_int(0b10, 2), 1),
        (mastic.vidpf.test_index_from_int(0b00, 2), 6),
        (mastic.vidpf.test_index_from_int(0b11, 2), 7),
        (mastic.vidpf.test_index_from_int(0b01, 2), 5),
        (mastic.vidpf.test_index_from_int(0b11, 2), 2)
    ]
    gen_test_vec_for_vdaf(
        vdaf_test_vec_path,
        mastic,
        agg_param,
        ctx,
        measurements,
        test_vec_instance=2,
    )

    # Test Vector 3
    mastic = Mastic(2, Sum(Field64, 2**2 - 1))
    agg_param = (
        1,
        (
            mastic.vidpf.test_index_from_int(0b00, 2),
            mastic.vidpf.test_index_from_int(0b01, 2)
        ),
        True,
    )
    measurements = [
        (mastic.vidpf.test_index_from_int(0b10, 2), 3),
        (mastic.vidpf.test_index_from_int(0b00, 2), 2),
        (mastic.vidpf.test_index_from_int(0b11, 2), 0),
        (mastic.vidpf.test_index_from_int(0b01, 2), 1),
        (mastic.vidpf.test_index_from_int(0b01, 2), 2)
    ]
    gen_test_vec_for_vdaf(
        vdaf_test_vec_path,
        mastic,
        agg_param,
        ctx,
        measurements,
        test_vec_instance=3,
    )
