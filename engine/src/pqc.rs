//! QUANTUM-READY SECURITY — hybrid post-quantum cryptography for report/evidence
//! integrity and export confidentiality, with algorithm agility via suite IDs.
//!
//! * Signatures: Ed25519 + ML-DSA-65 (FIPS 204). Both must verify.
//! * Encryption: X25519 + ML-KEM-768 (FIPS 203) → HKDF-SHA-256 → AES-256-GCM.
//! * Keys are derived from a 32-byte master seed held in the macOS Keychain and sent
//!   to the engine over stdin; no private key is ever written to disk.
//!
//! NOTE: the RustCrypto `ml-kem`/`ml-dsa` crates implement the final FIPS standards
//! and pass NIST vectors upstream, but have not had an independent audit. The hybrid
//! construction keeps classical security if a PQ implementation flaw were found.

use anyhow::{anyhow, bail, Result};
use base64::Engine;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

pub const SIG_SUITE: &str = "AD-SIG-1:Ed25519+ML-DSA-65";
pub const KEM_SUITE: &str = "AD-KEM-1:X25519+ML-KEM-768/HKDF-SHA256/AES-256-GCM";
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

fn sub(master: &[u8; 32], label: &str, len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(b"ARGENT-DEFENDER-PQC-v1"), master);
    let mut out = vec![0u8; len];
    hk.expand(label.as_bytes(), &mut out).expect("hkdf len");
    out
}

pub fn random32() -> [u8; 32] {
    let mut s = [0u8; 32];
    getrandom::fill(&mut s).expect("OS RNG");
    s
}

struct Keys {
    ed: ed25519_dalek::SigningKey,
    mldsa: ml_dsa::SigningKey<ml_dsa::MlDsa65>,
    x: x25519_dalek::StaticSecret,
    mlkem: ml_kem::DecapsulationKey<ml_kem::MlKem768>,
}

fn keys(master: &[u8; 32]) -> Keys {
    let ed: [u8; 32] = sub(master, "ed25519", 32).try_into().unwrap();
    let md: [u8; 32] = sub(master, "ml-dsa-65", 32).try_into().unwrap();
    let xs: [u8; 32] = sub(master, "x25519", 32).try_into().unwrap();
    let mk: [u8; 64] = sub(master, "ml-kem-768", 64).try_into().unwrap();
    Keys {
        ed: ed25519_dalek::SigningKey::from_bytes(&ed),
        mldsa: ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&md.into()),
        x: x25519_dalek::StaticSecret::from(xs),
        mlkem: ml_kem::DecapsulationKey::<ml_kem::MlKem768>::from_seed(mk.into()),
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PublicBundle {
    pub sig_suite: String,
    pub kem_suite: String,
    pub ed25519: String,
    pub ml_dsa_65: String,
    pub x25519: String,
    pub ml_kem_768: String,
    pub fingerprint: String,
}

pub fn public_bundle(master: &[u8; 32]) -> PublicBundle {
    use ml_kem::KeyExport;
    let k = keys(master);
    let ed = k.ed.verifying_key().to_bytes().to_vec();
    let md = k.mldsa.as_ref().encode().to_vec();
    let x = x25519_dalek::PublicKey::from(&k.x).to_bytes().to_vec();
    let mk = k.mlkem.encapsulation_key().to_bytes().to_vec();
    let fp = crate::hashing::sha256_hex(&[ed.clone(), md.clone(), x.clone(), mk.clone()].concat());
    PublicBundle { sig_suite: SIG_SUITE.into(), kem_suite: KEM_SUITE.into(), ed25519: B64.encode(ed), ml_dsa_65: B64.encode(md), x25519: B64.encode(x), ml_kem_768: B64.encode(mk), fingerprint: fp[..32].to_string() }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct HybridSignature {
    pub suite: String,
    pub signed_sha256: String,
    pub ed25519: String,
    pub ml_dsa_65: String,
    pub signer_fingerprint: String,
    pub signed_at: String,
}

pub fn sign(master: &[u8; 32], msg: &[u8]) -> HybridSignature {
    use ed25519_dalek::Signer as _;
    let k = keys(master);
    let digest = crate::hashing::sha256_hex(msg);
    let ctx = format!("{SIG_SUITE}|{digest}");
    let s1 = k.ed.sign(ctx.as_bytes()).to_bytes().to_vec();
    let s2: ml_dsa::Signature<ml_dsa::MlDsa65> = k.mldsa.sign(ctx.as_bytes());
    HybridSignature { suite: SIG_SUITE.into(), signed_sha256: digest, ed25519: B64.encode(s1), ml_dsa_65: B64.encode(s2.encode().to_vec()),
        signer_fingerprint: public_bundle(master).fingerprint, signed_at: crate::db::now() }
}

pub fn verify(pubb: &PublicBundle, msg: &[u8], sig: &HybridSignature) -> Result<()> {
    use ml_dsa::signature::Verifier as _;
    if sig.suite != SIG_SUITE { bail!("unsupported signature suite {}", sig.suite); }
    let digest = crate::hashing::sha256_hex(msg);
    if digest != sig.signed_sha256 { bail!("content hash mismatch: document was modified"); }
    let ctx = format!("{SIG_SUITE}|{digest}");
    let edpk: [u8; 32] = B64.decode(&pubb.ed25519)?.try_into().map_err(|_| anyhow!("ed25519 key length"))?;
    let edpk = ed25519_dalek::VerifyingKey::from_bytes(&edpk)?;
    let eds: [u8; 64] = B64.decode(&sig.ed25519)?.try_into().map_err(|_| anyhow!("ed25519 sig length"))?;
    edpk.verify_strict(ctx.as_bytes(), &ed25519_dalek::Signature::from_bytes(&eds)).map_err(|_| anyhow!("Ed25519 signature invalid"))?;
    let mdpk_b = B64.decode(&pubb.ml_dsa_65)?;
    let enc = ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa65>::try_from(mdpk_b.as_slice()).map_err(|_| anyhow!("ML-DSA key length"))?;
    let mdpk = ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::decode(&enc);
    let mds = ml_dsa::Signature::<ml_dsa::MlDsa65>::try_from(B64.decode(&sig.ml_dsa_65)?.as_slice()).map_err(|_| anyhow!("ML-DSA signature malformed"))?;
    mdpk.verify(ctx.as_bytes(), &mds).map_err(|_| anyhow!("ML-DSA-65 signature invalid"))?;
    Ok(())
}

#[derive(Serialize, Deserialize)]
pub struct Envelope {
    pub suite: String,
    pub recipient_fingerprint: String,
    pub x25519_ephemeral: String,
    pub ml_kem_ciphertext: String,
    pub nonce: String,
    pub ciphertext: String,
}

fn kdf(ss_x: &[u8], ss_k: &[u8], eph: &[u8], ct: &[u8]) -> [u8; 32] {
    let ikm = [ss_x, ss_k].concat();
    let hk = Hkdf::<Sha256>::new(Some(&[eph, ct].concat()), &ikm);
    let mut k = [0u8; 32];
    hk.expand(KEM_SUITE.as_bytes(), &mut k).unwrap();
    k
}

pub fn encrypt(recipient: &PublicBundle, plaintext: &[u8]) -> Result<Envelope> {
    use aes_gcm::aead::{Aead, KeyInit};
    use ml_kem::TryKeyInit;
    let xpk: [u8; 32] = B64.decode(&recipient.x25519)?.try_into().map_err(|_| anyhow!("x25519 key"))?;
    let eph = x25519_dalek::StaticSecret::from(random32());
    let eph_pub = x25519_dalek::PublicKey::from(&eph).to_bytes();
    let ss_x = eph.diffie_hellman(&x25519_dalek::PublicKey::from(xpk)).to_bytes();
    let ekb = B64.decode(&recipient.ml_kem_768)?;
    let ek = ml_kem::EncapsulationKey::<ml_kem::MlKem768>::new_from_slice(&ekb).map_err(|_| anyhow!("ML-KEM key invalid"))?;
    let m = random32();
    let (ct, ss_k) = ek.encapsulate_deterministic(&m.into());
    let key = kdf(&ss_x, ss_k.as_slice(), &eph_pub, ct.as_slice());
    let nonce = &random32()[..12];
    let cipher = aes_gcm::Aes256Gcm::new_from_slice(&key).map_err(|_| anyhow!("key"))?;
    let c = cipher.encrypt(nonce.try_into().map_err(|_| anyhow!("nonce"))?, plaintext).map_err(|_| anyhow!("encrypt"))?;
    Ok(Envelope { suite: KEM_SUITE.into(), recipient_fingerprint: recipient.fingerprint.clone(), x25519_ephemeral: B64.encode(eph_pub),
        ml_kem_ciphertext: B64.encode(ct.as_slice()), nonce: B64.encode(nonce), ciphertext: B64.encode(c) })
}

pub fn decrypt(master: &[u8; 32], env: &Envelope) -> Result<Vec<u8>> {
    use aes_gcm::aead::{Aead, KeyInit};
    use ml_kem::Decapsulate;
    if env.suite != KEM_SUITE { bail!("unsupported suite {}", env.suite); }
    let k = keys(master);
    let eph: [u8; 32] = B64.decode(&env.x25519_ephemeral)?.try_into().map_err(|_| anyhow!("eph"))?;
    let ss_x = k.x.diffie_hellman(&x25519_dalek::PublicKey::from(eph)).to_bytes();
    let ctb = B64.decode(&env.ml_kem_ciphertext)?;
    let ct = ml_kem::Ciphertext::<ml_kem::MlKem768>::try_from(ctb.as_slice()).map_err(|_| anyhow!("ML-KEM ciphertext length"))?;
    let ss_k = k.mlkem.decapsulate(&ct);
    let key = kdf(&ss_x, ss_k.as_slice(), &eph, &ctb);
    let cipher = aes_gcm::Aes256Gcm::new_from_slice(&key).map_err(|_| anyhow!("key"))?;
    let nonce = B64.decode(&env.nonce)?;
    cipher.decrypt(nonce.as_slice().try_into().map_err(|_| anyhow!("nonce"))?, B64.decode(&env.ciphertext)?.as_slice()).map_err(|_| anyhow!("authentication failed: wrong key or tampered ciphertext"))
}

pub fn read_master_stdin() -> Result<[u8; 32]> {
    let mut s = String::new();
    std::io::stdin().read_line(&mut s)?;
    let v = hex::decode(s.trim()).map_err(|_| anyhow!("master seed must be 64 hex chars on stdin"))?;
    v.try_into().map_err(|_| anyhow!("master seed must be 32 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hybrid_sign_verify_and_tamper() {
        let m = [42u8; 32];
        let p = public_bundle(&m);
        let s = sign(&m, b"report body");
        verify(&p, b"report body", &s).unwrap();
        assert!(verify(&p, b"report b0dy", &s).is_err());
        let mut s2 = s.clone();
        let mut raw = B64.decode(&s2.ml_dsa_65).unwrap();
        raw[10] ^= 1;
        s2.ml_dsa_65 = B64.encode(raw);
        assert!(verify(&p, b"report body", &s2).unwrap_err().to_string().contains("ML-DSA"));
        let other = public_bundle(&[1u8; 32]);
        assert!(verify(&other, b"report body", &s).is_err());
        // deterministic key derivation
        assert_eq!(public_bundle(&m).fingerprint, p.fingerprint);
    }
    #[test]
    fn hybrid_kem_roundtrip() {
        let m = [7u8; 32];
        let env = encrypt(&public_bundle(&m), b"evidence export").unwrap();
        assert_eq!(decrypt(&m, &env).unwrap(), b"evidence export");
        assert!(decrypt(&[8u8; 32], &env).is_err());
    }
}
