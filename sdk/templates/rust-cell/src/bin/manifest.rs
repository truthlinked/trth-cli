use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let manifest_json = truthlinked_cell::manifest_json();
    let out_path = env::var("TRUTHLINKED_MANIFEST_OUT").unwrap_or_else(|_| {
        let mut path = PathBuf::from(
            env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string()),
        );
        path.push("manifest.auto.json");
        path.to_string_lossy().to_string()
    });
    let _ = fs::write(out_path, manifest_json);
}
