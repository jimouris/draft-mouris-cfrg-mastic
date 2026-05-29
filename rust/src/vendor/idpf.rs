// SPDX-License-Identifier: MIT
//
// Vendored from `libprio-rs` at commit 4e497a2 (`src/idpf.rs`). These helpers
// are `pub(crate)`/private upstream so are not accessible to consumers of the
// `prio` crate. The implementations below are byte-for-byte copies of the
// upstream versions.

use core::iter::zip;

use subtle::{Choice, ConditionallySelectable};

pub(crate) fn xor_seeds(left: &[u8; 16], right: &[u8; 16]) -> [u8; 16] {
    let mut seed = [0u8; 16];
    for (a, (b, c)) in left.iter().zip(right.iter().zip(seed.iter_mut())) {
        *c = a ^ b;
    }
    seed
}

fn and_seeds(left: &[u8; 16], right: &[u8; 16]) -> [u8; 16] {
    let mut seed = [0u8; 16];
    for (a, (b, c)) in left.iter().zip(right.iter().zip(seed.iter_mut())) {
        *c = a & b;
    }
    seed
}

/// Take a control bit, and fan it out into a byte array that can be used as a mask for XOF seeds,
/// without branching. If the control bit input is 0, all bytes will be equal to 0, and if the
/// control bit input is 1, all bytes will be equal to 255.
fn control_bit_to_seed_mask(control: Choice) -> [u8; 16] {
    let mask = -(control.unwrap_u8() as i8) as u8;
    [mask; 16]
}

/// Take two seeds and a control bit, and return the first seed if the control bit is zero, or the
/// XOR of the two seeds if the control bit is one. This does not branch on the control bit.
pub(crate) fn conditional_xor_seeds(
    normal_input: &[u8; 16],
    switched_input: &[u8; 16],
    control: Choice,
) -> [u8; 16] {
    xor_seeds(
        normal_input,
        &and_seeds(switched_input, &control_bit_to_seed_mask(control)),
    )
}

/// Interchange the contents of seeds if the choice is 1, otherwise seeds remain unchanged.
pub(crate) fn conditional_swap_seed(lhs: &mut [u8; 16], rhs: &mut [u8; 16], choice: Choice) {
    zip(lhs, rhs).for_each(|(a, b)| u8::conditional_swap(a, b, choice));
}
