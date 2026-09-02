//! Gate: uf-oauth-boot + oauth-boot-host are members of this workspace.
//!
//! Featureless sibling-source contract (gauge / neutrino pattern).

#![allow(missing_docs)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn uf_oauth_boot_workspace_members_happy_path() {
    let root =
        fs::read_to_string(workspace_root().join("Cargo.toml")).expect("workspace Cargo.toml");
    for member in [".", "examples/oauth-boot-host"] {
        assert!(
            root.contains(&format!("\"{member}\"")),
            "workspace must list {member}"
        );
    }
    assert!(
        workspace_root()
            .join("examples/oauth-boot-host")
            .join("Cargo.toml")
            .is_file(),
        "missing crate dir examples/oauth-boot-host"
    );
}
