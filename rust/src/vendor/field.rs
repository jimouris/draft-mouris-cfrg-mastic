// SPDX-License-Identifier: MIT
//
// Vendored from `libprio-rs` at commit 4e497a2 (`src/field.rs`). These helpers
// are `pub(crate)` upstream so are not accessible to consumers of the `prio`
// crate. The implementations below are byte-for-byte copies of the upstream
// versions.

use prio::codec::CodecError;
// `Encode` must be in scope for the `elem.encode(bytes)` call in
// `encode_fieldvec` to resolve. `FieldElement: Encode` upstream.
#[allow(unused_imports)]
use prio::codec::Encode;
use prio::field::FieldElement;

use std::io::{Cursor, Read};

pub(crate) fn sub_assign_vector<F: FieldElement>(a: &mut [F], b: impl IntoIterator<Item = F>) {
    let mut count = 0;
    for (x, y) in a.iter_mut().zip(b) {
        *x -= y;
        count += 1;
    }
    assert_eq!(a.len(), count);
}

pub(crate) fn add_assign_vector<F: FieldElement>(a: &mut [F], b: impl IntoIterator<Item = F>) {
    let mut count = 0;
    for (x, y) in a.iter_mut().zip(b) {
        *x += y;
        count += 1;
    }
    assert_eq!(a.len(), count);
}

/// `encode_fieldvec` serializes a type that is equivalent to a vector of field elements.
#[inline(always)]
pub(crate) fn encode_fieldvec<F: FieldElement, T: AsRef<[F]>>(
    val: T,
    bytes: &mut Vec<u8>,
) -> Result<(), CodecError> {
    for elem in val.as_ref() {
        elem.encode(bytes)?;
    }
    Ok(())
}

/// `decode_fieldvec` deserializes some number of field elements from a cursor, and advances the
/// cursor's position.
pub(crate) fn decode_fieldvec<F: FieldElement>(
    count: usize,
    input: &mut Cursor<&[u8]>,
) -> Result<Vec<F>, CodecError> {
    let mut vec = Vec::with_capacity(count);
    let mut buffer = [0u8; 64];
    assert!(
        buffer.len() >= F::ENCODED_SIZE,
        "field is too big for buffer"
    );
    for _ in 0..count {
        input.read_exact(&mut buffer[..F::ENCODED_SIZE])?;
        vec.push(
            F::try_from(&buffer[..F::ENCODED_SIZE]).map_err(|e| CodecError::Other(Box::new(e)))?,
        );
    }
    Ok(vec)
}
