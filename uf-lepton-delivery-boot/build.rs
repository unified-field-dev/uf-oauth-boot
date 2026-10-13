//! Valence model codegen for `schemas/*_valence_schema.rs`.

fn main() {
    let Ok(out_dir) = std::env::var("OUT_DIR") else {
        std::process::exit(1);
    };
    let out_dir = std::path::PathBuf::from(out_dir);
    let schemas_dir = std::path::PathBuf::from("schemas");

    println!("cargo:rerun-if-changed=schemas/");

    if let Err(error) = valence_codegen::generate_models(&valence_codegen::CodegenConfig {
        schemas_dir,
        out_dir,
        file_suffix: "_valence_schema.rs",
        trait_file_suffix: "_valence_trait.rs",
    }) {
        panic!("valence codegen failed: {error}");
    }
}
