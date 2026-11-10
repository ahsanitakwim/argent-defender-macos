//! Streaming multi-hash engine (SHA-256 / SHA-1 / MD5) with an mtime/size cache
//! used by incremental scans.

use anyhow::Result;
use md5::Md5;
use serde::Serialize;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Hashes {
    pub sha256: String,
    pub sha1: String,
    pub md5: String,
    pub size: u64,
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub fn hash_reader<R: Read>(mut r: R) -> Result<Hashes> {
    let (mut a, mut b, mut c) = (Sha256::new(), Sha1::new(), Md5::new());
    let mut buf = vec![0u8; 1 << 20];
    let mut size = 0u64;
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        size += n as u64;
        a.update(&buf[..n]);
        b.update(&buf[..n]);
        c.update(&buf[..n]);
    }
    Ok(Hashes { sha256: hex::encode(a.finalize()), sha1: hex::encode(b.finalize()), md5: hex::encode(c.finalize()), size })
}

pub fn hash_file(p: &Path) -> Result<Hashes> {
    hash_reader(File::open(p)?)
}

pub fn sha256_file(p: &Path) -> Result<String> {
    let mut f = File::open(p)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn known_vectors() {
        let h = hash_reader(&b"abc"[..]).unwrap();
        assert_eq!(h.sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(h.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(h.md5, "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(h.size, 3);
    }
}
