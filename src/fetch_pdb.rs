use std::io::Read;

pub fn build_url(guid: String) -> String {
    format!("http://msdl.microsoft.com/download/symbols/shell32.pdb/{guid}/shell32.pdb")
}

<<<<<<< HEAD
pub fn fetch(url: String) -> Result<Vec<u8>, String> {
    // perform network call but return friendly errors instead of panicking
    match ureq::get(url.as_str()).call() {
        Ok(resp) => {
            let len: usize = if resp.has("Content-Length") {
                resp.header("Content-Length").unwrap_or("0").parse().unwrap_or(0)
            } else {
                15_000_000
            };
            let mut buf: Vec<u8> = Vec::with_capacity(len);
            resp.into_reader()
                .take(u64::MAX)
                .read_to_end(&mut buf)
                .map_err(|e| format!("Failed reading response body: {e}"))?;
            Ok(buf)
        }
        Err(e) => {
            // surface HTTP status when present
            match e {
                ureq::Error::Status(code, _) => Err(format!("HTTP error when fetching PDB: {}", code)),
                other => Err(format!("Network error when fetching PDB: {}", other)),
            }
        }
    }
=======
/// Returns None if the symbol server responds 404 (PDB not yet uploaded).
/// Panics on any other network or HTTP error.
pub fn try_fetch(url: String) -> Option<Vec<u8>> {
    let resp = match ureq::get(url.as_str()).call() {
        Ok(r) => r,
        Err(ureq::Error::Status(404, _)) => {
            println!("Symbol server returned 404 — PDB not yet available.");
            return None;
        }
        Err(e) => panic!("Failed to fetch PDB: {e}"),
    };

    let len: usize = if resp.has("Content-Length") {
        resp.header("Content-Length").unwrap().parse().unwrap()
    } else {
        // last time i checked, the file was about 11.6MB, so this should be fine
        15_000_000
    };

    let mut buf: Vec<u8> = Vec::with_capacity(len);
    resp.into_reader()
        .take(u64::MAX)
        .read_to_end(&mut buf)
        .unwrap();
    Some(buf)
>>>>>>> jcnnik/master
}
