# Dependency & Licence Report

## Shipped inside the application

| Component | Licence | How used |
|---|---|---|
| ARGENT DEFENDER (Swift app + Rust engine) | Proprietary (owner) | — |
| Apple frameworks (SwiftUI, Charts, WebKit, Security) | Apple SDK licence | System frameworks, not redistributed |
| Rust crates (statically linked into `argent-engine`) | All permissive — see table below | YARA-X (BSD-3-Clause), RustCrypto (MIT/Apache-2.0), rusqlite + bundled SQLite (MIT / public domain), rayon, zip, plist, ureq, clap, serde … |

No GPL/LGPL/AGPL/MPL code is linked into the shipped binaries (verified with `cargo metadata`). Note `CDLA-Permissive-2.0` (webpki-roots CA data), `Unicode-3.0` (ICU data used by `idna`) and `bzip2-1.0.6` — all permissive, attribution required.

## External tools (NOT bundled; installed by the user, invoked as separate processes)

| Tool | Licence | Notes |
|---|---|---|
| Android platform-tools (adb) | Apache-2.0 | Device access |
| libimobiledevice suite | LGPL-2.1 | iPhone pairing, info, backups |
| ClamAV | GPL-2.0 | Optional second engine |
| apksigner (Android SDK build-tools) | Apache-2.0 | Optional cryptographic APK verification |
| llama.cpp (`llama-server`) | MIT | Optional local LLM narrative |
| Quark-Engine, JADX, Apktool, ipsw, tshark, Zeek | GPL-3.0 / Apache-2.0 / Apache-2.0 / MIT / GPL-2.0 / BSD-3 | Detected only (analyst tools) |

## Data sources

| Source | Terms | Notes |
|---|---|---|
| abuse.ch URLhaus / ThreatFox / MalwareBazaar | CC0 per abuse.ch terms of use; API/exports may need a free Auth-Key | Recorded per dataset in `intel_feed.license` |
| User-imported STIX2 / MISP / lists | As provided by the source | Licence captured at import time |

Upstream licences and attributions must be preserved when redistributing; copy this file (and the crate table) into release artefacts — the build script places it in `Contents/Resources/licenses/`.

## Rust crate inventory (x86_64/aarch64-apple-darwin, 360 crates)

| Crate | Version | License |
|---|---|---|
| addr2line | 0.26.1 | Apache-2.0 OR MIT |
| adler2 | 2.0.1 | 0BSD OR MIT OR Apache-2.0 |
| aead | 0.6.1 | MIT OR Apache-2.0 |
| aes | 0.9.4 | MIT OR Apache-2.0 |
| aes-gcm | 0.11.1 | Apache-2.0 OR MIT |
| aes-kw | 0.3.1 | MIT OR Apache-2.0 |
| aho-corasick | 1.1.5 | Unlicense OR MIT |
| allocator-api2 | 0.2.21 | MIT OR Apache-2.0 |
| annotate-snippets | 0.12.17 | MIT OR Apache-2.0 |
| anstream | 1.0.0 | MIT OR Apache-2.0 |
| anstyle | 1.0.14 | MIT OR Apache-2.0 |
| anstyle-parse | 1.0.0 | MIT OR Apache-2.0 |
| anstyle-query | 1.1.5 | MIT OR Apache-2.0 |
| anyhow | 1.0.104 | MIT OR Apache-2.0 |
| arbitrary | 1.5.0 | MIT OR Apache-2.0 |
| ascii_tree | 0.1.1 | MIT |
| asn1-rs | 0.7.2 | MIT OR Apache-2.0 |
| asn1-rs-derive | 0.6.0 | MIT OR Apache-2.0 |
| asn1-rs-impl | 0.2.0 | MIT/Apache-2.0 |
| async-trait | 0.1.92 | MIT OR Apache-2.0 |
| autocfg | 1.5.1 | Apache-2.0 OR MIT |
| base16ct | 1.0.0 | Apache-2.0 OR MIT |
| base64 | 0.23.1 | MIT OR Apache-2.0 |
| base64ct | 1.8.3 | Apache-2.0 OR MIT |
| bincode | 2.0.1 | MIT |
| bincode_derive | 2.0.1 | MIT |
| bitflags | 2.13.2 | MIT OR Apache-2.0 |
| bitvec | 1.1.1 | MIT |
| block-buffer | 0.10.4 | MIT OR Apache-2.0 |
| block-buffer | 0.12.1 | MIT OR Apache-2.0 |
| block-padding | 0.4.2 | MIT OR Apache-2.0 |
| bstr | 1.13.1 | MIT OR Apache-2.0 |
| bumpalo | 3.20.3 | MIT OR Apache-2.0 |
| bytes | 1.12.1 | MIT |
| bzip2 | 0.6.1 | MIT OR Apache-2.0 |
| cbc | 0.2.1 | MIT OR Apache-2.0 |
| cc | 1.11.1 | MIT OR Apache-2.0 |
| cfg-if | 1.0.5 | MIT OR Apache-2.0 |
| cfg_aliases | 0.2.2 | MIT |
| chrono | 0.4.45 | MIT OR Apache-2.0 |
| cipher | 0.5.2 | MIT OR Apache-2.0 |
| clap | 4.6.7 | MIT OR Apache-2.0 |
| clap_builder | 4.6.7 | MIT OR Apache-2.0 |
| clap_derive | 4.6.7 | MIT OR Apache-2.0 |
| clap_lex | 1.1.1 | MIT OR Apache-2.0 |
| cmov | 0.5.4 | Apache-2.0 OR MIT |
| cobs | 0.3.0 | MIT OR Apache-2.0 |
| colorchoice | 1.0.5 | MIT OR Apache-2.0 |
| const-oid | 0.10.2 | Apache-2.0 OR MIT |
| constant_time_eq | 0.6.1 | CC0-1.0 OR MIT-0 OR Apache-2.0 |
| core-foundation-sys | 0.8.7 | MIT OR Apache-2.0 |
| countme | 3.0.1 | MIT OR Apache-2.0 |
| cpp_demangle | 0.5.1 | MIT OR Apache-2.0 |
| cpubits | 0.1.1 | MIT OR Apache-2.0 |
| cpufeatures | 0.2.17 | MIT OR Apache-2.0 |
| cpufeatures | 0.3.1 | MIT OR Apache-2.0 |
| cranelift-assembler-x64 | 0.135.8 | Apache-2.0 WITH LLVM-exception |
| cranelift-assembler-x64-meta | 0.135.8 | Apache-2.0 WITH LLVM-exception |
| cranelift-bforest | 0.135.8 | Apache-2.0 WITH LLVM-exception |
| cranelift-bitset | 0.135.8 | Apache-2.0 WITH LLVM-exception |
| cranelift-codegen | 0.135.8 | Apache-2.0 WITH LLVM-exception |
| cranelift-codegen-meta | 0.135.8 | Apache-2.0 WITH LLVM-exception |
| cranelift-codegen-shared | 0.135.8 | Apache-2.0 WITH LLVM-exception |
| cranelift-control | 0.135.8 | Apache-2.0 WITH LLVM-exception |
| cranelift-entity | 0.135.8 | Apache-2.0 WITH LLVM-exception |
| cranelift-frontend | 0.135.8 | Apache-2.0 WITH LLVM-exception |
| cranelift-isle | 0.135.8 | Apache-2.0 WITH LLVM-exception |
| cranelift-native | 0.135.8 | Apache-2.0 WITH LLVM-exception |
| cranelift-srcgen | 0.135.8 | Apache-2.0 WITH LLVM-exception |
| crc32fast | 1.5.5 | MIT OR Apache-2.0 |
| crossbeam-deque | 0.8.8 | MIT OR Apache-2.0 |
| crossbeam-epoch | 0.9.21 | MIT OR Apache-2.0 |
| crossbeam-utils | 0.8.23 | MIT OR Apache-2.0 |
| crypto-bigint | 0.7.11 | Apache-2.0 OR MIT |
| crypto-common | 0.1.7 | MIT OR Apache-2.0 |
| crypto-common | 0.2.2 | MIT OR Apache-2.0 |
| crypto-primes | 0.7.2 | Apache-2.0 OR MIT |
| ctr | 0.10.1 | MIT OR Apache-2.0 |
| ctutils | 0.4.8 | Apache-2.0 OR MIT |
| curve25519-dalek | 5.0.0 | BSD-3-Clause |
| curve25519-dalek-derive | 0.1.1 | MIT/Apache-2.0 |
| daachorse | 5.1.0 | MIT OR Apache-2.0 |
| darling | 0.24.1 | MIT |
| darling_core | 0.24.1 | MIT |
| darling_macro | 0.24.1 | MIT |
| data-encoding | 2.11.1 | MIT |
| deflate64 | 0.1.12 | MIT |
| der | 0.8.3 | Apache-2.0 OR MIT |
| der-parser | 10.0.0 | MIT OR Apache-2.0 |
| deranged | 0.5.9 | MIT OR Apache-2.0 |
| digest | 0.10.7 | MIT OR Apache-2.0 |
| digest | 0.11.3 | MIT OR Apache-2.0 |
| displaydoc | 0.2.7 | MIT OR Apache-2.0 |
| dsa | 0.7.0 | Apache-2.0 OR MIT |
| ecdsa | 0.17.0 | Apache-2.0 OR MIT |
| ed25519 | 3.0.0 | Apache-2.0 OR MIT |
| ed25519-dalek | 3.0.0 | BSD-3-Clause |
| either | 1.19.0 | MIT OR Apache-2.0 |
| elliptic-curve | 0.14.3 | Apache-2.0 OR MIT |
| embedded-io | 0.4.0 | MIT OR Apache-2.0 |
| embedded-io | 0.6.1 | MIT OR Apache-2.0 |
| equivalent | 1.0.3 | Apache-2.0 OR MIT |
| errno | 0.3.14 | MIT OR Apache-2.0 |
| fallible-iterator | 0.3.0 | MIT/Apache-2.0 |
| fallible-streaming-iterator | 0.1.9 | MIT/Apache-2.0 |
| fastrand | 2.5.0 | Apache-2.0 OR MIT |
| ff | 0.14.0 | MIT/Apache-2.0 |
| find-msvc-tools | 0.1.15 | MIT OR Apache-2.0 |
| flate2 | 1.1.11 | MIT OR Apache-2.0 |
| fnv | 1.0.7 | Apache-2.0 / MIT |
| foldhash | 0.2.0 | Zlib |
| funty | 2.0.0 | MIT |
| futures | 0.3.34 | MIT OR Apache-2.0 |
| futures-channel | 0.3.34 | MIT OR Apache-2.0 |
| futures-core | 0.3.34 | MIT OR Apache-2.0 |
| futures-io | 0.3.34 | MIT OR Apache-2.0 |
| futures-sink | 0.3.34 | MIT OR Apache-2.0 |
| futures-task | 0.3.34 | MIT OR Apache-2.0 |
| futures-util | 0.3.34 | MIT OR Apache-2.0 |
| generic-array | 0.14.7 | MIT |
| getrandom | 0.2.17 | MIT OR Apache-2.0 |
| getrandom | 0.4.3 | MIT OR Apache-2.0 |
| ghash | 0.6.0 | Apache-2.0 OR MIT |
| gimli | 0.32.3 | MIT OR Apache-2.0 |
| gimli | 0.33.0 | MIT OR Apache-2.0 |
| globset | 0.4.21 | Unlicense OR MIT |
| globwalk | 0.9.1 | MIT |
| group | 0.14.0 | MIT/Apache-2.0 |
| hashbrown | 0.14.5 | MIT OR Apache-2.0 |
| hashbrown | 0.16.1 | MIT OR Apache-2.0 |
| hashbrown | 0.17.1 | MIT OR Apache-2.0 |
| hashlink | 0.12.2 | MIT OR Apache-2.0 |
| heck | 0.5.0 | MIT OR Apache-2.0 |
| hex | 0.4.3 | MIT OR Apache-2.0 |
| hkdf | 0.13.0 | MIT OR Apache-2.0 |
| hmac | 0.13.0 | MIT OR Apache-2.0 |
| home | 0.5.12 | MIT OR Apache-2.0 |
| http | 1.5.0 | MIT OR Apache-2.0 |
| httparse | 1.10.1 | MIT OR Apache-2.0 |
| hybrid-array | 0.4.15 | MIT OR Apache-2.0 |
| iana-time-zone | 0.1.65 | MIT OR Apache-2.0 |
| icu_collections | 2.4.0 | Unicode-3.0 |
| icu_locale_core | 2.4.0 | Unicode-3.0 |
| icu_normalizer | 2.4.0 | Unicode-3.0 |
| icu_normalizer_data | 2.4.0 | Unicode-3.0 |
| icu_properties | 2.4.0 | Unicode-3.0 |
| icu_properties_data | 2.4.0 | Unicode-3.0 |
| icu_provider | 2.4.0 | Unicode-3.0 |
| id-arena | 2.3.0 | MIT/Apache-2.0 |
| ident_case | 1.0.1 | MIT/Apache-2.0 |
| idna | 1.1.0 | MIT OR Apache-2.0 |
| idna_adapter | 1.2.2 | Apache-2.0 OR MIT |
| ignore | 0.4.34 | Unlicense OR MIT |
| indexmap | 2.14.2 | Apache-2.0 OR MIT |
| inout | 0.2.6 | MIT OR Apache-2.0 |
| intaglio | 1.15.1 | Apache-2.0 OR MIT |
| inventory | 0.3.25 | MIT OR Apache-2.0 |
| ipnet | 2.12.2 | MIT OR Apache-2.0 |
| is_terminal_polyfill | 1.70.2 | MIT OR Apache-2.0 |
| itertools | 0.14.0 | MIT OR Apache-2.0 |
| itertools | 0.15.0 | MIT OR Apache-2.0 |
| itoa | 1.0.19 | MIT OR Apache-2.0 |
| jobserver | 0.1.35 | MIT OR Apache-2.0 |
| keccak | 0.2.2 | Apache-2.0 OR MIT |
| kem | 0.3.0 | Apache-2.0 OR MIT |
| lazy_static | 1.5.1 | MIT OR Apache-2.0 |
| leb128 | 0.2.7 | MIT OR Apache-2.0 |
| leb128fmt | 0.1.0 | MIT OR Apache-2.0 |
| libbz2-rs-sys | 0.2.6 | bzip2-1.0.6 |
| libc | 0.2.191 | MIT OR Apache-2.0 |
| libm | 0.2.16 | MIT |
| libsqlite3-sys | 0.39.1 | MIT |
| litemap | 0.8.3 | Unicode-3.0 |
| log | 0.4.35 | MIT OR Apache-2.0 |
| logos | 0.16.1 | MIT OR Apache-2.0 |
| logos-codegen | 0.16.1 | MIT OR Apache-2.0 |
| logos-derive | 0.16.1 | MIT OR Apache-2.0 |
| lzma-rust2 | 0.25.0 | Apache-2.0 |
| mach2 | 0.6.0 | BSD-2-Clause OR MIT OR Apache-2.0 |
| md-5 | 0.11.0 | MIT OR Apache-2.0 |
| md2 | 0.11.0 | MIT OR Apache-2.0 |
| memchr | 2.8.3 | Unlicense OR MIT |
| memmap2 | 0.9.12 | MIT OR Apache-2.0 |
| memoffset | 0.9.1 | MIT |
| minimal-lexical | 0.2.1 | MIT/Apache-2.0 |
| miniz_oxide | 0.9.1 | MIT OR Zlib OR Apache-2.0 |
| ml-dsa | 0.1.2 | Apache-2.0 OR MIT |
| ml-kem | 0.3.4 | Apache-2.0 OR MIT |
| module-lattice | 0.2.4 | Apache-2.0 OR MIT |
| nix | 0.31.3 | MIT |
| nom | 7.1.3 | MIT |
| nom | 8.0.0 | MIT |
| num-bigint | 0.4.8 | MIT OR Apache-2.0 |
| num-conv | 0.2.2 | MIT OR Apache-2.0 |
| num-derive | 0.5.1 | MIT OR Apache-2.0 |
| num-integer | 0.1.47 | MIT OR Apache-2.0 |
| num-traits | 0.2.19 | MIT OR Apache-2.0 |
| object | 0.39.1 | Apache-2.0 OR MIT |
| oid-registry | 0.8.1 | MIT OR Apache-2.0 |
| once_cell | 1.21.4 | MIT OR Apache-2.0 |
| p256 | 0.14.0 | Apache-2.0 OR MIT |
| p384 | 0.14.0 | Apache-2.0 OR MIT |
| pbkdf2 | 0.13.0 | MIT OR Apache-2.0 |
| pem-rfc7468 | 1.0.0 | Apache-2.0 OR MIT |
| percent-encoding | 2.3.2 | MIT OR Apache-2.0 |
| pin-project-lite | 0.2.17 | Apache-2.0 OR MIT |
| pkcs1 | 0.8.0 | Apache-2.0 OR MIT |
| pkcs8 | 0.11.0 | Apache-2.0 OR MIT |
| pkg-config | 0.3.34 | MIT OR Apache-2.0 |
| plist | 1.10.3 | MIT |
| polyval | 0.7.3 | Apache-2.0 OR MIT |
| postcard | 1.1.3 | MIT OR Apache-2.0 |
| potential_utf | 0.1.6 | Unicode-3.0 |
| powerfmt | 0.2.1 | MIT OR Apache-2.0 |
| ppmd-rust | 1.5.2 | CC0-1.0 OR MIT-0 |
| primefield | 0.14.0 | Apache-2.0 OR MIT |
| primeorder | 0.14.0 | Apache-2.0 OR MIT |
| proc-macro2 | 1.0.107 | MIT OR Apache-2.0 |
| protobuf | 3.7.2 | MIT |
| protobuf-codegen | 3.7.2 | MIT |
| protobuf-parse | 3.7.2 | MIT |
| protobuf-support | 3.7.2 | MIT |
| psl | 2.1.250 | MIT/Apache-2.0 |
| psl-types | 2.0.11 | MIT/Apache-2.0 |
| pulley-interpreter | 48.0.8 | Apache-2.0 WITH LLVM-exception |
| pulley-macros | 48.0.8 | Apache-2.0 WITH LLVM-exception |
| quick-xml | 0.42.0 | MIT |
| quote | 1.0.47 | MIT OR Apache-2.0 |
| radium | 0.7.0 | MIT |
| rand_core | 0.10.1 | MIT OR Apache-2.0 |
| rayon | 1.12.0 | MIT OR Apache-2.0 |
| rayon-core | 1.13.0 | MIT OR Apache-2.0 |
| regalloc2 | 0.15.2 | Apache-2.0 WITH LLVM-exception |
| regex | 1.13.1 | MIT OR Apache-2.0 |
| regex-automata | 0.4.18 | MIT OR Apache-2.0 |
| regex-syntax | 0.8.11 | MIT OR Apache-2.0 |
| rfc6979 | 0.6.0 | Apache-2.0 OR MIT |
| ring | 0.17.14 | Apache-2.0 AND ISC |
| rowan | 0.17.0 | MIT OR Apache-2.0 |
| roxmltree | 0.21.2 | MIT OR Apache-2.0 |
| rsa | 0.10.0 | MIT OR Apache-2.0 |
| rusqlite | 0.41.1 | MIT |
| rustc-demangle | 0.1.28 | MIT/Apache-2.0 |
| rustc-hash | 1.1.0 | Apache-2.0/MIT |
| rustc-hash | 2.1.3 | Apache-2.0 OR MIT |
| rustc_version | 0.4.1 | MIT OR Apache-2.0 |
| rusticata-macros | 4.1.0 | MIT/Apache-2.0 |
| rustix | 0.38.44 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| rustix | 1.1.6 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| rustls | 0.23.46 | Apache-2.0 OR ISC OR MIT |
| rustls-pki-types | 1.15.1 | MIT OR Apache-2.0 |
| rustls-webpki | 0.103.16 | ISC |
| rustversion | 1.0.23 | MIT OR Apache-2.0 |
| same-file | 1.0.6 | Unlicense/MIT |
| sec1 | 0.8.1 | Apache-2.0 OR MIT |
| semver | 1.0.28 | MIT OR Apache-2.0 |
| serde | 1.0.229 | MIT OR Apache-2.0 |
| serde_core | 1.0.229 | MIT OR Apache-2.0 |
| serde_derive | 1.0.229 | MIT OR Apache-2.0 |
| serde_json | 1.0.154 | MIT OR Apache-2.0 |
| serdect | 0.4.3 | Apache-2.0 OR MIT |
| sha1 | 0.11.0 | MIT OR Apache-2.0 |
| sha2 | 0.10.9 | MIT OR Apache-2.0 |
| sha2 | 0.11.1 | MIT OR Apache-2.0 |
| sha3 | 0.12.0 | MIT OR Apache-2.0 |
| shake | 0.1.0 | MIT OR Apache-2.0 |
| shlex | 2.0.1 | MIT OR Apache-2.0 |
| signature | 3.0.0 | Apache-2.0 OR MIT |
| simd-adler32 | 0.3.10 | MIT |
| simd_cesu8 | 1.2.0 | Apache-2.0 OR MIT |
| simdutf8 | 0.1.5 | MIT OR Apache-2.0 |
| slab | 0.4.12 | MIT |
| smallvec | 1.16.5 | MIT OR Apache-2.0 |
| spki | 0.8.1 | Apache-2.0 OR MIT |
| sponge-cursor | 0.1.0 | MIT OR Apache-2.0 |
| stable_deref_trait | 1.2.1 | MIT OR Apache-2.0 |
| strsim | 0.11.1 | MIT |
| strum_macros | 0.28.0 | MIT |
| subtle | 2.6.1 | BSD-3-Clause |
| syn | 2.0.119 | MIT OR Apache-2.0 |
| syn | 3.0.10 | MIT OR Apache-2.0 |
| synstructure | 0.13.2 | MIT |
| synstructure | 0.14.0 | MIT |
| tap | 1.0.1 | MIT |
| target-lexicon | 0.13.5 | Apache-2.0 WITH LLVM-exception |
| tempfile | 3.27.0 | MIT OR Apache-2.0 |
| termcolor | 1.4.1 | Unlicense OR MIT |
| text-size | 1.1.1 | MIT OR Apache-2.0 |
| thiserror | 1.0.69 | MIT OR Apache-2.0 |
| thiserror | 2.0.21 | MIT OR Apache-2.0 |
| thiserror-impl | 1.0.69 | MIT OR Apache-2.0 |
| thiserror-impl | 2.0.21 | MIT OR Apache-2.0 |
| time | 0.3.55 | MIT OR Apache-2.0 |
| time-core | 0.1.9 | MIT OR Apache-2.0 |
| time-macros | 0.2.32 | MIT OR Apache-2.0 |
| tinystr | 0.8.5 | Unicode-3.0 |
| tinyzip | 0.4.0 | MIT |
| typed-path | 0.13.0 | MIT OR Apache-2.0 |
| typenum | 1.20.1 | MIT OR Apache-2.0 |
| unicode-ident | 1.0.27 | (MIT OR Apache-2.0) AND Unicode-3.0 |
| unicode-width | 0.2.3 | MIT OR Apache-2.0 |
| universal-hash | 0.6.1 | MIT OR Apache-2.0 |
| untrusted | 0.9.0 | ISC |
| unty | 0.0.4 | MIT OR Apache-2.0 |
| ureq | 3.5.1 | MIT OR Apache-2.0 |
| ureq-proto | 0.7.1 | MIT OR Apache-2.0 |
| utf8-zero | 0.8.1 | MIT OR Apache-2.0 |
| utf8_iter | 1.1.0 | Apache-2.0 OR MIT |
| utf8parse | 0.2.2 | Apache-2.0 OR MIT |
| utf_types | 1.0.0 | Apache-2.0 OR MIT |
| uuid | 1.29.2 | Apache-2.0 OR MIT |
| vcpkg | 0.2.15 | MIT/Apache-2.0 |
| version_check | 0.9.5 | MIT/Apache-2.0 |
| virtue | 0.0.18 | MIT |
| walkdir | 2.5.0 | Unlicense/MIT |
| walrus | 0.27.3 | MIT/Apache-2.0 |
| walrus-macro | 0.26.0 | MIT/Apache-2.0 |
| wasm-encoder | 0.245.1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| wasm-encoder | 0.254.2 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| wasmparser | 0.245.1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| wasmparser | 0.254.2 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| wasmprinter | 0.254.2 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| wasmtime | 48.0.8 | Apache-2.0 WITH LLVM-exception |
| wasmtime-environ | 48.0.8 | Apache-2.0 WITH LLVM-exception |
| wasmtime-internal-component-util | 48.0.8 | Apache-2.0 WITH LLVM-exception |
| wasmtime-internal-core | 48.0.8 | Apache-2.0 WITH LLVM-exception |
| wasmtime-internal-cranelift | 48.0.8 | Apache-2.0 WITH LLVM-exception |
| wasmtime-internal-fiber | 48.0.8 | Apache-2.0 WITH LLVM-exception |
| wasmtime-internal-jit-debug | 48.0.8 | Apache-2.0 WITH LLVM-exception |
| wasmtime-internal-jit-icache-coherence | 48.0.8 | Apache-2.0 WITH LLVM-exception |
| wasmtime-internal-unwinder | 48.0.8 | Apache-2.0 WITH LLVM-exception |
| wasmtime-internal-versioned-export-macros | 48.0.8 | Apache-2.0 WITH LLVM-exception |
| webpki-roots | 1.0.11 | CDLA-Permissive-2.0 |
| which | 4.4.2 | MIT |
| wnaf | 0.14.1 | Apache-2.0 OR MIT |
| writeable | 0.6.4 | Unicode-3.0 |
| wyz | 0.5.1 | MIT |
| x25519-dalek | 3.0.0 | BSD-3-Clause |
| x509-parser | 0.18.1 | MIT OR Apache-2.0 |
| yansi | 1.0.1 | MIT OR Apache-2.0 |
| yara-x | 1.23.0 | BSD-3-Clause |
| yara-x-macros | 1.23.0 | BSD-3-Clause |
| yara-x-parser | 1.23.0 | BSD-3-Clause |
| yara-x-proto | 1.23.0 | BSD-3-Clause |
| yoke | 0.8.4 | Unicode-3.0 |
| yoke-derive | 0.8.4 | Unicode-3.0 |
| zerofrom | 0.1.8 | Unicode-3.0 |
| zerofrom-derive | 0.1.8 | Unicode-3.0 |
| zeroize | 1.9.1 | Apache-2.0 OR MIT |
| zeroize_derive | 1.5.0 | Apache-2.0 OR MIT |
| zerotrie | 0.2.5 | Unicode-3.0 |
| zerovec | 0.11.9 | Unicode-3.0 |
| zerovec-derive | 0.11.7 | Unicode-3.0 |
| zip | 9.5.0 | MIT |
| zlib-rs | 0.6.8 | Zlib |
| zmij | 1.0.23 | MIT |
| zopfli | 0.8.4 | Apache-2.0 |
| zstd | 0.14.3 | BSD-3-Clause |
| zstd-safe | 8.2.0 | BSD-3-Clause |
| zstd-sys | 2.1.2+zstd.1.5.7 | BSD-3-Clause |