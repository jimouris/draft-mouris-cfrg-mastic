// SPDX-License-Identifier: MIT
//
// Vendored from `libprio-rs` at commit 4e497a2 (`src/vdaf/xof.rs`).
//
// `XofTurboShake128::from_seed_slice` is `pub(crate)` upstream, so we cannot
// call it from outside the `prio` crate. The Mastic protocol requires it for
// initialising the XOF with seeds of length other than `SEED_SIZE` (notably
// the empty seed used by the onehot/payload checks and the 16-byte VIDPF seed
// used by node proofs); the public `Xof::init` requires `&[u8; 32]` and so is
// not a substitute.
//
// This module exposes the same byte-level framing on top of public
// `sha3::TurboShake128`. The output bytes are intended to match prio's
// implementation exactly.

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    TurboShake128, TurboShake128Core,
};

/// Value of the domain separation byte "D" used by `XofTurboShake128` when
/// invoking TurboSHAKE128. Mirrors the upstream constant.
const XOF_TURBO_SHAKE_128_DOMAIN_SEPARATION: u8 = 1;

/// A drop-in replacement for `prio::vdaf::xof::XofTurboShake128` that exposes
/// the `from_seed_slice` semantics from outside the `prio` crate. Only the
/// methods needed by Mastic are implemented.
#[derive(Clone, Debug)]
pub(crate) struct MasticXof(TurboShake128);

impl MasticXof {
    /// Initialise the XOF with a seed of arbitrary length (including zero)
    /// and a sequence of domain-separation byte strings. Byte-for-byte
    /// equivalent to `prio::vdaf::xof::XofTurboShake128::from_seed_slice`.
    pub(crate) fn from_seed_slice(seed_bytes: &[u8], dst_parts: &[&[u8]]) -> Self {
        let mut xof = Self(TurboShake128::from_core(TurboShake128Core::new(
            XOF_TURBO_SHAKE_128_DOMAIN_SEPARATION,
        )));

        let dst_len = dst_parts.iter().map(|p| p.len()).sum::<usize>();
        let Ok(dst_len) = u16::try_from(dst_len) else {
            panic!("dst must not exceed 65535 bytes");
        };

        let Ok(seed_len) = u8::try_from(seed_bytes.len()) else {
            panic!("seed must not exceed 255 bytes");
        };

        Update::update(&mut xof.0, &dst_len.to_le_bytes());
        for dst_part in dst_parts {
            Update::update(&mut xof.0, dst_part);
        }
        Update::update(&mut xof.0, &seed_len.to_le_bytes());
        Update::update(&mut xof.0, seed_bytes);
        xof
    }

    /// Absorb additional bytes into the XOF state.
    pub(crate) fn update(&mut self, data: &[u8]) {
        Update::update(&mut self.0, data);
    }

    /// Finalise and squeeze 32 bytes from the XOF. Equivalent to calling
    /// `into_seed()` on `prio::vdaf::xof::XofTurboShake128` and then taking
    /// the raw seed bytes.
    pub(crate) fn into_seed_bytes(self) -> [u8; 32] {
        let mut reader = self.0.finalize_xof();
        let mut out = [0u8; 32];
        reader.read(&mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prio::vdaf::xof::{Xof, XofTurboShake128};

    /// Check that `MasticXof::from_seed_slice` is byte-compatible with
    /// `prio::vdaf::xof::XofTurboShake128::init` for 32-byte seeds.
    /// `init` and `from_seed_slice` are equivalent inside `prio` when the seed
    /// is exactly the canonical length.
    #[test]
    fn from_seed_slice_matches_init_for_32_byte_seed() {
        let seed = [0xAAu8; 32];
        let dst = [&b"mastic"[..], &b"\x00\x00"[..], &b"context"[..]];

        let mut ours = MasticXof::from_seed_slice(&seed, &dst);
        ours.update(b"binder");
        let ours_out = ours.into_seed_bytes();

        let mut theirs = XofTurboShake128::init(&seed, &dst);
        theirs.update(b"binder");
        let theirs_out = *theirs.into_seed().as_ref();

        assert_eq!(ours_out, theirs_out);
    }
}
