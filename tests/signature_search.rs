use uwd2::cache_pdb;
use std::path::PathBuf;

#[test]
fn find_signature_in_asset() {
    // pick a short pattern from assets/banner.png (must exist in repo)
    let path = PathBuf::from("assets/banner.png");
    assert!(path.exists(), "asset file missing");
    // read file and pick a 4-byte pattern from middle
    let data = std::fs::read(&path).expect("read asset");
    assert!(data.len() > 100, "asset too small");
    let pos = data.len() / 2;
    let sig = &data[pos..pos+4];
    let cands = cache_pdb::find_signature_in_path(sig, path.to_str().unwrap()).expect("search failed");
    assert!(!cands.is_empty(), "should find signature in same file");
}
