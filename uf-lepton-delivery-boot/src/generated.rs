#![allow(
    dead_code,
    unused_imports,
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::restriction
)]
//! Valence-codegen output for the delivery settings schema (`build.rs` + `schemas/`).

use crate::privacy_policies::LEPTON_DELIVERY_GATE;
use gauge::privacy_policies::SUPER_USER_GROUP_MEMBER;
use valence::privacy_policies::common::{BLOCK_ALL, SYSTEM_ONLY};

include!(concat!(env!("OUT_DIR"), "/generated_models.rs"));
