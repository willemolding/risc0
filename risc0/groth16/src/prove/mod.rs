// Copyright 2025 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! # Groth16 Prover

#[cfg(feature = "cuda")]
mod cuda;
#[cfg(not(feature = "cuda"))]
mod docker;
mod seal_format;
mod seal_to_json;

use anyhow::Result;

use crate::Seal;

pub use self::seal_to_json::to_json;

/// Produce a Groth16 proof from an `identity_p254` seal.
pub fn shrink_wrap(identity_p254_seal_bytes: &[u8]) -> Result<Seal> {
    cfg_if::cfg_if! {
        if #[cfg(feature = "cuda")] {
            self::cuda::shrink_wrap(identity_p254_seal_bytes, Circuit::StarkToSnark)
        } else {
            self::docker::shrink_wrap(identity_p254_seal_bytes)
        }
    }
}

/// Produce a Groth16 Blake3 proof from an `identity_p254` seal plus
/// additional inputs required for this circuit
pub fn shrink_wrap_blake3(
    identity_p254_seal_bytes: &[u8],
    journal_bytes: [u8; 32],
    pre_state_digest: [u8; 32],
    post_state_digest: [u8; 32],
    control_id: [u8; 32],
    succinct_control_root: [u8; 32],
) -> Result<Seal> {
    cfg_if::cfg_if! {
        if #[cfg(feature = "cuda")] {
            self::cuda::shrink_wrap(identity_p254_seal_bytes, Circuit::StarkToSnarkBlake3{ journal_bytes, pre_state_digest, post_state_digest, control_id, succinct_control_root })
        } else {
            panic!("shrink_wrap requires the 'cuda' feature to be enabled");
        }
    }
}

#[derive(Debug)]
pub(crate) enum Circuit {
    StarkToSnark,
    StarkToSnarkBlake3 {
        journal_bytes: [u8; 32],
        pre_state_digest: [u8; 32],
        post_state_digest: [u8; 32],
        control_id: [u8; 32],
        succinct_control_root: [u8; 32],
    },
}
