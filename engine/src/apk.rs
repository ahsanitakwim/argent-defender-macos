//! Native APK static analysis: binary AndroidManifest (AXML) decoding, signing-scheme
//! inspection (v1/v2/v3), certificate fingerprints and component inventory.
//! No external tools needed; apksigner (if installed) is used for cryptographic verification.

use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;
use std::collections::BTreeSet;
use std::io::{Read, Seek};
use std::path::Path;

// ------------------------------------------------------------------ AXML

#[derive(Debug, Clone, Serialize)]
pub struct XmlAttr {
    pub name: String,
    pub res_id: u32,
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct XmlElem {
    pub depth: usize,
    pub name: String,
    pub attrs: Vec<XmlAttr>,
}

impl XmlElem {
    pub fn get(&self, name: &str) -> Option<&str> {
        let id = android_attr_id(name);
        self.attrs
            .iter()
            .find(|a| a.name == name || (id != 0 && a.res_id == id))
            .map(|a| a.value.as_str())
    }
}

fn android_attr_id(name: &str) -> u32 {
    match name {
        "label" => 0x0101_0001,
        "name" => 0x0101_0003,
        "permission" => 0x0101_0006,
        "exported" => 0x0101_0010,
        "protectionLevel" => 0x0101_0009,
        "debuggable" => 0x0101_000f,
        "minSdkVersion" => 0x0101_020c,
        "versionCode" => 0x0101_021b,
        "versionName" => 0x0101_021c,
        "targetSdkVersion" => 0x0101_0270,
        "allowBackup" => 0x0101_0280,
        "usesCleartextTraffic" => 0x0101_04ec,
        _ => 0,
    }
}

fn u16le(b: &[u8], o: usize) -> Result<u16> {
    b.get(o..o + 2).map(|s| u16::from_le_bytes([s[0], s[1]])).ok_or_else(|| anyhow!("AXML truncated at {o}"))
}
fn u32le(b: &[u8], o: usize) -> Result<u32> {
    b.get(o..o + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]])).ok_or_else(|| anyhow!("AXML truncated at {o}"))
}

fn read_string_pool(b: &[u8], start: usize) -> Result<Vec<String>> {
    let header_size = u16le(b, start + 2)? as usize;
    let count = u32le(b, start + 8)? as usize;
    let flags = u32le(b, start + 16)?;
    let strings_start = u32le(b, start + 20)? as usize;
    let utf8 = flags & (1 << 8) != 0;
    if count > 1_000_000 {
        bail!("implausible string count");
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let off = u32le(b, start + header_size + i * 4)? as usize;
        let mut p = start + strings_start + off;
        let s = if utf8 {
            // utf16 length (1-2 bytes) then utf8 length (1-2 bytes)
            let l0 = *b.get(p).ok_or_else(|| anyhow!("pool"))? as usize;
            p += if l0 & 0x80 != 0 { 2 } else { 1 };
            let l1 = *b.get(p).ok_or_else(|| anyhow!("pool"))? as usize;
            let len = if l1 & 0x80 != 0 {
                let l2 = *b.get(p + 1).ok_or_else(|| anyhow!("pool"))? as usize;
                p += 2;
                ((l1 & 0x7f) << 8) | l2
            } else {
                p += 1;
                l1
            };
            String::from_utf8_lossy(b.get(p..p + len).ok_or_else(|| anyhow!("pool str"))?).into_owned()
        } else {
            let mut len = u16le(b, p)? as usize;
            p += 2;
            if len & 0x8000 != 0 {
                len = ((len & 0x7fff) << 16) | u16le(b, p)? as usize;
                p += 2;
            }
            let units: Vec<u16> = (0..len).map(|k| u16le(b, p + k * 2)).collect::<Result<_>>()?;
            String::from_utf16_lossy(&units)
        };
        out.push(s);
    }
    Ok(out)
}

/// Decode a binary AndroidManifest.xml into a flat list of elements (with depth).
pub fn parse_axml(b: &[u8]) -> Result<Vec<XmlElem>> {
    if u16le(b, 0)? != 0x0003 {
        bail!("not a binary XML document");
    }
    let mut pos = u16le(b, 2)? as usize;
    let mut strings: Vec<String> = vec![];
    let mut res_ids: Vec<u32> = vec![];
    let mut elems = vec![];
    let mut depth = 0usize;
    let s = |strings: &Vec<String>, idx: u32| -> String {
        if idx == u32::MAX { String::new() } else { strings.get(idx as usize).cloned().unwrap_or_default() }
    };
    while pos + 8 <= b.len() {
        let ty = u16le(b, pos)?;
        let hsz = u16le(b, pos + 2)? as usize;
        let size = u32le(b, pos + 4)? as usize;
        if size < 8 || pos + size > b.len() {
            break;
        }
        match ty {
            0x0001 => strings = read_string_pool(b, pos)?,
            0x0180 => {
                res_ids = (0..(size - hsz) / 4).map(|i| u32le(b, pos + hsz + i * 4)).collect::<Result<_>>()?;
            }
            0x0102 => {
                let ext = pos + hsz;
                let name = s(&strings, u32le(b, ext + 4)?);
                let attr_start = u16le(b, ext + 8)? as usize;
                let attr_size = u16le(b, ext + 10)? as usize;
                let attr_count = u16le(b, ext + 12)? as usize;
                let mut attrs = vec![];
                for i in 0..attr_count {
                    let a = ext + attr_start + i * attr_size.max(20);
                    let name_idx = u32le(b, a + 4)?;
                    let raw = u32le(b, a + 8)?;
                    let dtype = *b.get(a + 15).ok_or_else(|| anyhow!("attr"))?;
                    let data = u32le(b, a + 16)?;
                    let value = if raw != u32::MAX {
                        s(&strings, raw)
                    } else {
                        match dtype {
                            0x03 => s(&strings, data),
                            0x10 => (data as i32).to_string(),
                            0x11 => format!("0x{data:08x}"),
                            0x12 => (data != 0).to_string(),
                            0x01 => format!("@0x{data:08x}"),
                            _ => format!("{data}"),
                        }
                    };
                    attrs.push(XmlAttr {
                        name: s(&strings, name_idx),
                        res_id: res_ids.get(name_idx as usize).copied().unwrap_or(0),
                        value,
                    });
                }
                elems.push(XmlElem { depth, name, attrs });
                depth += 1;
            }
            0x0103 => depth = depth.saturating_sub(1),
            _ => {}
        }
        pos += size;
    }
    if elems.is_empty() {
        bail!("no elements decoded");
    }
    Ok(elems)
}

// ------------------------------------------------------------------ Manifest model

#[derive(Debug, Clone, Serialize, Default)]
pub struct Component {
    pub kind: String,
    pub name: String,
    pub exported: Option<bool>,
    pub permission: Option<String>,
    pub actions: Vec<String>,
    pub categories: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Manifest {
    pub package: String,
    pub version_code: Option<String>,
    pub version_name: Option<String>,
    pub min_sdk: Option<String>,
    pub target_sdk: Option<String>,
    pub label: Option<String>,
    pub permissions: BTreeSet<String>,
    pub declared_permissions: Vec<String>,
    pub debuggable: bool,
    pub allow_backup: Option<bool>,
    pub cleartext_traffic: Option<bool>,
    pub components: Vec<Component>,
}

impl Manifest {
    pub fn services_with_permission(&self, perm: &str) -> Vec<&Component> {
        self.components.iter().filter(|c| c.permission.as_deref() == Some(perm)).collect()
    }
    pub fn has_launcher(&self) -> bool {
        self.components.iter().any(|c| {
            (c.kind == "activity" || c.kind == "activity-alias")
                && c.actions.iter().any(|a| a == "android.intent.action.MAIN")
                && c.categories.iter().any(|a| a == "android.intent.category.LAUNCHER" || a == "android.intent.category.LEANBACK_LAUNCHER")
        })
    }
    pub fn receivers_with_action(&self, action: &str) -> Vec<&Component> {
        self.components.iter().filter(|c| c.actions.iter().any(|a| a == action)).collect()
    }
}

pub fn manifest_from_elems(elems: &[XmlElem]) -> Manifest {
    let mut m = Manifest::default();
    let mut current: Option<Component> = None;
    let mut comp_depth = 0usize;
    for e in elems {
        if let Some(c) = current.take() {
            if e.depth <= comp_depth {
                m.components.push(c);
            } else {
                current = Some(c);
            }
        }
        match e.name.as_str() {
            "manifest" => {
                m.package = e.get("package").unwrap_or_default().to_string();
                m.version_code = e.get("versionCode").map(String::from);
                m.version_name = e.get("versionName").map(String::from);
            }
            "uses-sdk" => {
                m.min_sdk = e.get("minSdkVersion").map(String::from);
                m.target_sdk = e.get("targetSdkVersion").map(String::from);
            }
            "uses-permission" | "uses-permission-sdk-23" | "uses-permission-sdk-m" => {
                if let Some(p) = e.get("name") {
                    m.permissions.insert(p.to_string());
                }
            }
            "permission" => {
                if let Some(p) = e.get("name") {
                    m.declared_permissions.push(p.to_string());
                }
            }
            "application" => {
                m.label = e.get("label").filter(|l| !l.starts_with('@')).map(String::from);
                m.debuggable = e.get("debuggable") == Some("true");
                m.allow_backup = e.get("allowBackup").map(|v| v == "true");
                m.cleartext_traffic = e.get("usesCleartextTraffic").map(|v| v == "true");
            }
            "activity" | "activity-alias" | "service" | "receiver" | "provider" => {
                comp_depth = e.depth;
                current = Some(Component {
                    kind: e.name.clone(),
                    name: e.get("name").unwrap_or_default().to_string(),
                    exported: e.get("exported").map(|v| v == "true"),
                    permission: e.get("permission").map(String::from),
                    ..Default::default()
                });
            }
            "action" => {
                if let (Some(c), Some(n)) = (current.as_mut(), e.get("name")) {
                    c.actions.push(n.to_string());
                }
            }
            "category" => {
                if let (Some(c), Some(n)) = (current.as_mut(), e.get("name")) {
                    c.categories.push(n.to_string());
                }
            }
            _ => {}
        }
    }
    if let Some(c) = current {
        m.components.push(c);
    }
    m
}

// ------------------------------------------------------------------ Signing

#[derive(Debug, Clone, Serialize, Default)]
pub struct SigningInfo {
    pub v1_jar_signature: bool,
    pub v2: bool,
    pub v3: bool,
    pub v31: bool,
    pub certificates_sha256: Vec<String>,
    pub debug_certificate: bool,
    /// Result of `apksigner verify` when available; None when tool missing.
    pub apksigner_verified: Option<bool>,
    pub apksigner_output: Option<String>,
}

fn find_eocd(b: &[u8]) -> Option<usize> {
    if b.len() < 22 {
        return None;
    }
    let min = b.len().saturating_sub(22 + 65535);
    (min..=b.len() - 22).rev().find(|&i| b[i..i + 4] == [0x50, 0x4b, 0x05, 0x06])
}

fn lp_slices(mut b: &[u8]) -> Vec<&[u8]> {
    let mut out = vec![];
    while b.len() >= 4 {
        let n = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize;
        if 4 + n > b.len() {
            break;
        }
        out.push(&b[4..4 + n]);
        b = &b[4 + n..];
    }
    out
}

fn lp_first(b: &[u8]) -> Option<&[u8]> {
    lp_slices(b).into_iter().next()
}

/// Extract X.509 certificates from a v2/v3 signature-scheme block value.
fn scheme_certs(value: &[u8]) -> Vec<Vec<u8>> {
    let mut certs = vec![];
    if let Some(signers) = lp_first(value) {
        for signer in lp_slices(signers) {
            if let Some(signed_data) = lp_first(signer) {
                let parts = lp_slices(signed_data);
                if parts.len() >= 2 {
                    for c in lp_slices(parts[1]) {
                        certs.push(c.to_vec());
                    }
                }
            }
        }
    }
    certs
}

pub fn signing_block(b: &[u8]) -> SigningInfo {
    let mut info = SigningInfo::default();
    let Some(eocd) = find_eocd(b) else { return info };
    let cd = u32::from_le_bytes([b[eocd + 16], b[eocd + 17], b[eocd + 18], b[eocd + 19]]) as usize;
    if cd < 32 || cd > b.len() || &b[cd - 16..cd] != b"APK Sig Block 42" {
        return info;
    }
    let size = u64::from_le_bytes(b[cd - 24..cd - 16].try_into().unwrap()) as usize;
    if size + 8 > cd {
        return info;
    }
    let start = cd - size - 8;
    let mut p = start + 8;
    let end = cd - 24;
    while p + 12 <= end {
        let len = u64::from_le_bytes(b[p..p + 8].try_into().unwrap()) as usize;
        if len < 4 || p + 8 + len > end {
            break;
        }
        let id = u32::from_le_bytes(b[p + 8..p + 12].try_into().unwrap());
        let value = &b[p + 12..p + 8 + len];
        match id {
            0x7109_871a => info.v2 = true,
            0xf053_68c0 => info.v3 = true,
            0x1b93_ad61 => info.v31 = true,
            _ => {}
        }
        if matches!(id, 0x7109_871a | 0xf053_68c0 | 0x1b93_ad61) {
            for c in scheme_certs(value) {
                if c.windows(13).any(|w| w == b"Android Debug") {
                    info.debug_certificate = true;
                }
                let fp = crate::hashing::sha256_hex(&c);
                if !info.certificates_sha256.contains(&fp) {
                    info.certificates_sha256.push(fp);
                }
            }
        }
        p += 8 + len;
    }
    info
}

// ------------------------------------------------------------------ Entry points

#[derive(Debug, Clone, Serialize)]
pub struct ApkReport {
    pub path: String,
    pub hashes: crate::hashing::Hashes,
    pub manifest: Manifest,
    pub signing: SigningInfo,
    pub dex_files: Vec<String>,
    pub native_libs: Vec<String>,
    pub entries: usize,
}

pub fn analyze_apk(path: &Path) -> Result<ApkReport> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    analyze_apk_bytes(&bytes, &path.display().to_string())
}

pub fn analyze_apk_bytes(bytes: &[u8], label: &str) -> Result<ApkReport> {
    let hashes = crate::hashing::hash_reader(bytes)?;
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(bytes)).context("APK is not a valid ZIP archive")?;
    let manifest_bytes = read_entry(&mut z, "AndroidManifest.xml", 16 << 20)?;
    let manifest = manifest_from_elems(&parse_axml(&manifest_bytes)?);
    let mut dex = vec![];
    let mut libs = vec![];
    let mut v1 = false;
    for i in 0..z.len() {
        let name = z.by_index_raw(i).map(|f| f.name().map(|n| n.to_string()).unwrap_or_default()).unwrap_or_default();
        if name.ends_with(".dex") {
            dex.push(name.clone());
        }
        if name.starts_with("lib/") && name.ends_with(".so") {
            libs.push(name.clone());
        }
        let up = name.to_ascii_uppercase();
        if up.starts_with("META-INF/") && (up.ends_with(".RSA") || up.ends_with(".DSA") || up.ends_with(".EC")) {
            v1 = true;
        }
    }
    let mut signing = signing_block(bytes);
    signing.v1_jar_signature = v1;
    Ok(ApkReport { path: label.to_string(), hashes, manifest, signing, dex_files: dex, native_libs: libs, entries: z.len() })
}

pub fn read_entry<R: Read + Seek>(z: &mut zip::ZipArchive<R>, name: &str, cap: u64) -> Result<Vec<u8>> {
    let f = z.by_name(name).with_context(|| format!("{name} missing"))?;
    let mut buf = vec![];
    f.take(cap).read_to_end(&mut buf)?;
    Ok(buf)
}

/// Optional cryptographic verification with Android's apksigner (build-tools).
pub fn apksigner_verify(path: &Path, info: &mut SigningInfo) {
    if let Some(bin) = crate::tools::which("apksigner") {
        if let Ok(o) = std::process::Command::new(bin).args(["verify", "--verbose"]).arg(path).output() {
            info.apksigner_verified = Some(o.status.success());
            let txt = String::from_utf8_lossy(&o.stdout).to_string() + &String::from_utf8_lossy(&o.stderr);
            info.apksigner_output = Some(txt.chars().take(4000).collect());
        }
    }
}

#[cfg(test)]
pub mod testutil {
    //! Minimal AXML *encoder* used only to produce deterministic test manifests.
    pub struct AxmlBuilder {
        strings: Vec<String>,
        body: Vec<u8>,
    }
    impl AxmlBuilder {
        pub fn new() -> Self {
            AxmlBuilder { strings: vec![], body: vec![] }
        }
        fn idx(&mut self, s: &str) -> u32 {
            if let Some(i) = self.strings.iter().position(|x| x == s) {
                return i as u32;
            }
            self.strings.push(s.into());
            (self.strings.len() - 1) as u32
        }
        pub fn start(&mut self, name: &str, attrs: &[(&str, &str)]) -> &mut Self {
            let n = self.idx(name);
            let a: Vec<(u32, u32)> = attrs.iter().map(|(k, v)| (self.idx(k), self.idx(v))).collect();
            let size = 16 + 20 + a.len() * 20;
            let b = &mut self.body;
            b.extend(0x0102u16.to_le_bytes());
            b.extend(16u16.to_le_bytes());
            b.extend((size as u32).to_le_bytes());
            b.extend(1u32.to_le_bytes());
            b.extend(u32::MAX.to_le_bytes());
            b.extend(u32::MAX.to_le_bytes()); // ns
            b.extend(n.to_le_bytes());
            b.extend(20u16.to_le_bytes());
            b.extend(20u16.to_le_bytes());
            b.extend((a.len() as u16).to_le_bytes());
            b.extend([0u8; 6]);
            for (k, v) in a {
                b.extend(u32::MAX.to_le_bytes());
                b.extend(k.to_le_bytes());
                b.extend(v.to_le_bytes());
                b.extend(8u16.to_le_bytes());
                b.push(0);
                b.push(0x03);
                b.extend(v.to_le_bytes());
            }
            self
        }
        pub fn end(&mut self) -> &mut Self {
            let b = &mut self.body;
            b.extend(0x0103u16.to_le_bytes());
            b.extend(16u16.to_le_bytes());
            b.extend(24u32.to_le_bytes());
            b.extend([0u8; 16]);
            self
        }
        pub fn build(&self) -> Vec<u8> {
            let mut data = vec![];
            let mut offs = vec![];
            for s in &self.strings {
                offs.push(data.len() as u32);
                let u: Vec<u16> = s.encode_utf16().collect();
                data.extend((u.len() as u16).to_le_bytes());
                for c in u {
                    data.extend(c.to_le_bytes());
                }
                data.extend([0, 0]);
            }
            while data.len() % 4 != 0 {
                data.push(0);
            }
            let hdr = 28usize;
            let pool_size = hdr + offs.len() * 4 + data.len();
            let mut pool = vec![];
            pool.extend(0x0001u16.to_le_bytes());
            pool.extend((hdr as u16).to_le_bytes());
            pool.extend((pool_size as u32).to_le_bytes());
            pool.extend((offs.len() as u32).to_le_bytes());
            pool.extend(0u32.to_le_bytes());
            pool.extend(0u32.to_le_bytes());
            pool.extend(((hdr + offs.len() * 4) as u32).to_le_bytes());
            pool.extend(0u32.to_le_bytes());
            for o in offs {
                pool.extend(o.to_le_bytes());
            }
            pool.extend(data);
            let total = 8 + pool.len() + self.body.len();
            let mut out = vec![];
            out.extend(0x0003u16.to_le_bytes());
            out.extend(8u16.to_le_bytes());
            out.extend((total as u32).to_le_bytes());
            out.extend(pool);
            out.extend(&self.body);
            out
        }
    }

    /// Builds a small APK-shaped zip with the given manifest.
    pub fn make_apk(manifest: &[u8], extra: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Write;
        let mut cur = std::io::Cursor::new(Vec::new());
        {
            let mut w = zip::ZipWriter::new(&mut cur);
            let o: zip::write::SimpleFileOptions = Default::default();
            w.start_file("AndroidManifest.xml", o).unwrap();
            w.write_all(manifest).unwrap();
            for (n, d) in extra {
                w.start_file(*n, o).unwrap();
                w.write_all(d).unwrap();
            }
            w.finish().unwrap();
        }
        cur.into_inner()
    }

    pub fn sample_manifest(pkg: &str, perms: &[&str], accessibility: bool, launcher: bool) -> Vec<u8> {
        let mut b = AxmlBuilder::new();
        b.start("manifest", &[("package", pkg), ("versionName", "1.0")]);
        for p in perms {
            b.start("uses-permission", &[("name", p)]).end();
        }
        b.start("application", &[("label", "Sample")]);
        if launcher {
            b.start("activity", &[("name", ".Main")])
                .start("intent-filter", &[])
                .start("action", &[("name", "android.intent.action.MAIN")]).end()
                .start("category", &[("name", "android.intent.category.LAUNCHER")]).end()
                .end()
                .end();
        }
        if accessibility {
            b.start("service", &[("name", ".Acc"), ("permission", "android.permission.BIND_ACCESSIBILITY_SERVICE")])
                .start("intent-filter", &[])
                .start("action", &[("name", "android.accessibilityservice.AccessibilityService")]).end()
                .end()
                .end();
        }
        b.end().end();
        b.build()
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;

    #[test]
    fn decodes_manifest_components() {
        let m = sample_manifest("com.example.app", &["android.permission.INTERNET", "android.permission.SYSTEM_ALERT_WINDOW"], true, true);
        let apk = make_apk(&m, &[("classes.dex", b"dex\n035\0"), ("lib/arm64-v8a/libx.so", b"\x7fELF")]);
        let r = analyze_apk_bytes(&apk, "mem").unwrap();
        assert_eq!(r.manifest.package, "com.example.app");
        assert_eq!(r.manifest.version_name.as_deref(), Some("1.0"));
        assert!(r.manifest.permissions.contains("android.permission.SYSTEM_ALERT_WINDOW"));
        assert!(r.manifest.has_launcher());
        assert_eq!(r.manifest.services_with_permission("android.permission.BIND_ACCESSIBILITY_SERVICE").len(), 1);
        assert_eq!(r.dex_files, vec!["classes.dex"]);
        assert_eq!(r.native_libs.len(), 1);
        assert!(!r.signing.v2 && !r.signing.v1_jar_signature);
    }

    #[test]
    fn rejects_non_apk() {
        assert!(analyze_apk_bytes(b"not a zip", "x").is_err());
    }
}
