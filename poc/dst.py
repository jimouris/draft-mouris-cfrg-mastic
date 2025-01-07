"""
Domain separation tags for all XOF usages, collected all in one place in order
to make it easier to check that they're all distinct.
"""

from vdaf_poc.common import byte, to_le_bytes

# The version of this document. This should be `0` until the document
# gets adopted, at which point this should be synchronized with the
# latest wire-breaking working group draft.
VERSION: int = 0

# Mastic
USAGE_PROVE_RAND: int = 0
USAGE_WEIGHT_SHARE: int = 1
USAGE_PROOF_SHARE: int = 2
USAGE_QUERY_RAND: int = 3
USAGE_JOINT_RAND_SEED: int = 4
USAGE_JOINT_RAND_PART: int = 5
USAGE_JOINT_RAND: int = 6
USAGE_ONEHOT_CHECK: int = 7
USAGE_PAYLOAD_CHECK: int = 8
USAGE_EVAL_PROOF: int = 9

# VIDPF
USAGE_NODE_PROOF: int = 10
USAGE_EXTEND: int = 11
USAGE_CONVERT: int = 12


def dst(ctx: bytes, usage: int) -> bytes:
    assert usage in range(13)
    return b'mastic' + byte(VERSION) + byte(usage) + ctx


def dst_alg(ctx: bytes, usage: int, algorithm_id: int) -> bytes:
    assert usage in range(13)
    assert algorithm_id in range(2 ** 32 - 1)
    return b'mastic'\
        + byte(VERSION) \
        + byte(usage) \
        + to_le_bytes(algorithm_id, 4) \
        + ctx
