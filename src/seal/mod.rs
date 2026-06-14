// Copyright (c), Frank V. Castellucci
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// 32-byte address / object identifier.
/// BCS-serialized as 32 raw bytes, wire-compatible with sui_sdk_types::Address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ObjectID([u8; 32]);

#[allow(dead_code)]
impl ObjectID {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn inner(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn into_inner(self) -> [u8; 32] {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl FromStr for ObjectID {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s).map_err(|e| e.to_string())?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "ObjectID must be exactly 32 bytes (64 hex chars)".to_string())?;
        Ok(Self(arr))
    }
}

impl fmt::Display for ObjectID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

pub mod bindings;
pub mod core;
pub mod dem;
pub mod elgamal;
pub mod gf256;
pub mod ibe;
pub(crate) mod polynomial;
pub mod tss;
pub(crate) mod utils;
