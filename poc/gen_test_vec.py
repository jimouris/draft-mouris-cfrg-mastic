#!/usr/bin/env python3

import os

from vdaf_poc.test_utils import gen_test_vec_for_vdaf
from vdaf_poc.field import Field64, Field128
from vdaf_poc.flp_bbcggi19 import Count, Sum
from mastic import Mastic


# # The path where test vectors are generated.
TEST_VECTOR_PATH = os.environ.get('TEST_VECTOR_PATH', '../test_vec/')


if __name__ == '__main__':

    ctx = b'some application'
    vdaf_test_vec_path = TEST_VECTOR_PATH + "/mastic/"

    ## Count Test Vectors
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
    measurements = [
        (mastic.vidpf.test_index_from_int(0b10, 2), 1),
        (mastic.vidpf.test_index_from_int(0b00, 2), 1),
        (mastic.vidpf.test_index_from_int(0b11, 2), 1),
        (mastic.vidpf.test_index_from_int(0b01, 2), 1),
        (mastic.vidpf.test_index_from_int(0b11, 2), 1),
    ],
    gen_test_vec_for_vdaf(
        vdaf_test_vec_path,
        mastic,
        agg_param,
        ctx,
        measurements,
        0,
    )

    # Test Vector 1
    agg_param = (1, (mastic.vidpf.test_index_from_int(0b00, 2),
        mastic.vidpf.test_index_from_int(0b01, 2)), True),
    measurements = [
        (mastic.vidpf.test_index_from_int(0b10, 2), 1),
        (mastic.vidpf.test_index_from_int(0b00, 2), 1),
        (mastic.vidpf.test_index_from_int(0b11, 2), 1),
        (mastic.vidpf.test_index_from_int(0b01, 2), 1),
        (mastic.vidpf.test_index_from_int(0b01, 2), 0),
    ]
    gen_test_vec_for_vdaf(
        vdaf_test_vec_path,
        mastic,
        agg_param,
        ctx,
        measurements,
        1,
    )


    ## Sum Test Vectors
    # Test Vector 0
    mastic = Mastic(2, Sum(Field64, 2**3 - 1))
    agg_param = (0, (mastic.vidpf.test_index_from_int(0b0, 1),
        mastic.vidpf.test_index_from_int(0b1, 1)), True)
    measurements = [
        (mastic.vidpf.test_index_from_int(0b10, 2), 1),
        (mastic.vidpf.test_index_from_int(0b00, 2), 6),
        (mastic.vidpf.test_index_from_int(0b11, 2), 7),
        (mastic.vidpf.test_index_from_int(0b01, 2), 5),
        (mastic.vidpf.test_index_from_int(0b11, 2), 2),
    ]
    gen_test_vec_for_vdaf(
        vdaf_test_vec_path,
        mastic,
        agg_param,
        ctx,
        measurements,
        0,
    )

    # Test Vector 1
    mastic = Mastic(2, Sum(Field64, 2**2 - 1))
    agg_param = (1, (mastic.vidpf.test_index_from_int(0b00, 2),
        mastic.vidpf.test_index_from_int(0b01, 2)), True),
    measurements = [
        (mastic.vidpf.test_index_from_int(0b10, 2), 3),
        (mastic.vidpf.test_index_from_int(0b00, 2), 2),
        (mastic.vidpf.test_index_from_int(0b11, 2), 0),
        (mastic.vidpf.test_index_from_int(0b01, 2), 1),
        (mastic.vidpf.test_index_from_int(0b01, 2), 2),
    ]
    gen_test_vec_for_vdaf(
        vdaf_test_vec_path,
        mastic,
        agg_param,
        ctx,
        measurements,
        1,
    )

#     # Poplar1
#     poplar1_test_number = 0
#     tests: list[tuple[int, tuple[tuple[bool, ...], ...]]] = [
#         (0, ((False,), (True,))),
#         (1, ((False, False), (False, True), (True, False), (True, True))),
#         (
#             2,
#             (
#                 (False, False, False),
#                 (False, True, False),
#                 (True, False, False),
#                 (True, True, False),
#             ),
#         ),
#         (
#             3,
#             (
#                 (False, False, False, True),
#                 (False, False, True, True),
#                 (False, True, False, True),
#                 (False, True, True, True),
#                 (True, False, False, True),
#                 (True, True, False, True),
#                 (True, True, True, True),
#             ),
#         ),
#     ]
#     measurements: list[tuple[bool, ...]] = [(True, True, False, True)]
#     for (test_level, prefixes) in tests:
#         gen_test_vec_for_vdaf(
#             vdaf_test_vec_path,
#             vdaf_poplar1.Poplar1(4),
#             (test_level, prefixes),
#             ctx,
#             measurements,
#             poplar1_test_number,
#         )
#         poplar1_test_number += 1

#     tests = [
#         (0, ((False,), (True,))),
#         (10, (
#             (False,) * 11,
#             (True, True, False, False, True, False, False, False, False, False,
#              False),
#             (True, True, False, False, True, False, False, False, False, False,
#              True),
#             (True,) * 11,
#         )),
#     ]
#     measurements = [
#         (True, True, False, False, True, False, False, False, False, False,
#          True),
#     ]
#     for (test_level, prefixes) in tests:
#         gen_test_vec_for_vdaf(
#             vdaf_test_vec_path,
#             vdaf_poplar1.Poplar1(11),
#             (test_level, prefixes),
#             ctx,
#             measurements,
#             poplar1_test_number,
#         )
#         poplar1_test_number += 1

