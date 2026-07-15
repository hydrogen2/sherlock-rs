//! Manifest oracle — the Rust port of upstream `tests/test_manifest.py`.
//!
//! Deterministic and offline: validates the embedded `data.json` against its JSON
//! Schema, confirms every site parses into our typed `Site`, and pins the two
//! error-type expectations upstream also asserts.

use sherlock_rs::site::{self, ErrorType};

#[test]
fn manifest_matches_local_schema() {
    let data: serde_json::Value =
        serde_json::from_str(site::EMBEDDED_MANIFEST).expect("data.json parses as JSON");
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../resources/data.schema.json"))
            .expect("schema parses as JSON");

    let compiled = jsonschema::JSONSchema::compile(&schema).expect("schema compiles");
    // Collect into owned Strings right away so the error iterator's borrow of
    // `data`/`compiled` ends here, before either value is dropped.
    let errors: Vec<String> = match compiled.validate(&data) {
        Ok(()) => Vec::new(),
        Err(iter) => iter
            .map(|e| format!("{e} at {}", e.instance_path))
            .collect(),
    };
    assert!(
        errors.is_empty(),
        "manifest failed schema validation:\n{}",
        errors.join("\n")
    );
}

#[test]
fn every_site_parses_into_typed_site() {
    let manifest = site::load_embedded().expect("manifest parses into typed sites");
    // Upstream ships ~480 sites; guard against an accidental empty/half parse.
    assert!(
        manifest.len() > 400,
        "expected 400+ sites, got {}",
        manifest.len()
    );
}

#[test]
fn known_sites_have_expected_error_types() {
    let manifest = site::load_embedded().unwrap();
    // Same pins as upstream test_manifest.py::test_site_list_iterability.
    assert_eq!(manifest["GitHub"].error_type, ErrorType::StatusCode);
    assert_eq!(manifest["GitLab"].error_type, ErrorType::Message);
}
