// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

use fastcrypto::groups::{GroupElement, Scalar};
use fastcrypto::traits::AllowedRng;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct SecretKey<G: GroupElement>(G::ScalarType);

#[derive(Serialize, Deserialize, Clone)]
pub struct PublicKey<G: GroupElement>(G);

#[derive(Serialize, Deserialize, Clone)]
pub struct VerificationKey<G: GroupElement>(G);

impl<G: GroupElement> VerificationKey<G> {
    pub fn as_element(&self) -> &G {
        &self.0
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Encryption<G: GroupElement>(pub G, pub G);

pub fn genkey<G: GroupElement, VG: GroupElement<ScalarType = G::ScalarType>, R: AllowedRng>(
    rng: &mut R,
) -> (SecretKey<G>, PublicKey<G>, VerificationKey<VG>) {
    let sk = G::ScalarType::rand(rng);
    (
        SecretKey(sk),
        PublicKey(G::generator() * sk),
        VerificationKey(VG::generator() * sk),
    )
}

pub fn encrypt<G: GroupElement, R: AllowedRng>(
    rng: &mut R,
    msg: &G,
    pk: &PublicKey<G>,
) -> Encryption<G> {
    let r = G::ScalarType::rand(rng);
    Encryption(G::generator() * r, pk.0 * r + msg)
}

pub fn decrypt<G: GroupElement>(sk: &SecretKey<G>, e: &Encryption<G>) -> G {
    e.1 - e.0 * sk.0
}
