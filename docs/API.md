# ARGENT DEFENDER — Engine API (internal)

The macOS app talks to `argent-engine` (inside `Contents/MacOS/`) by launching it with arguments and reading **one JSON envelope** from stdout. The same CLI is usable by analysts and in CI.

```json
{"ok": true, "command": "scan /path", "data": { ... }, "error": null, "duration_ms": 234, "engine_version": "1.0.0"}
```

`ok=false` ⇒ `data=null`, `error` holds a human-readable cause chain; exit status 1.

**Global options:** `--db <path>` (env `ARGENT_DB`), `--pretty`.
**Secrets:** only via stdin (`--password-stdin`, `--auth-key-stdin`, PQC seed for `report --sign` / `pqc *`).

## Commands

| Command | Purpose | Key `data` fields |
|---|---|---|
| `env` | Host + tool detection, intel stats, rule status | `host{os,arch,os_version,cpu_model,logical_cpus,memory_bytes,apple_silicon}`, `tools[]{name,purpose,path,version,install_hint}`, `intel`, `rules` |
| `devices` | Detect Android (adb) + iPhone (libimobiledevice) | `android{available,devices[]{serial,state,model,transport}}`, `ios{available,devices[]{udid,name,product_type,ios_version,connection,paired}}` |
| `device-history` | Known devices | `[]{device_id,platform,model,os_version,last_scan,last_score}` |
| `android info --serial S` | getprop summary | manufacturer, model, version, patch, boot/encryption state |
| `android audit --serial S [--pull-apks DIR] [--third-party-only]` | Standard / Advanced Forensic audit | `info`, `apps[]` (AppProfile), `findings[]`, `anomalies[]`, `pulled_apks[]`, `risk`, `scan_id` |
| `ios info --udid U` · `ios audit --udid U [--min-ios N]` | Lockdown device audit | `info`, `findings`, `risk`, `scan_id` |
| `ios backup-create --udid U --out DIR` | `idevicebackup2 backup --full` | `output`, `path` |
| `ios backups [--root DIR]` | Discover Finder backups | `root`, `readable`, `backups[]{path,udid,device_name,ios_version,last_backup,encrypted}` |
| `ios analyze --backup DIR [--password-stdin] [--include-messages] [--min-ios N]` | Backup forensics (encrypted supported) | `summary`, `encrypted`, `installed_apps`, `files_indexed`, `urls_examined`, `processes_examined`, `timeline[]`, `findings`, `risk`, `gambling_classification`, `scan_id` |
| `apk FILE [--no-record]` | APK static analysis | `apk{hashes,manifest,signing,dex_files,native_libs}`, `profile`, `findings`, `risk`, `gambling_classification` |
| `scan PATH --mode quick\|full\|deep\|custom\|incremental [--ext a,b] [--max-size N] [--clamav] [--threads N] [--rules-dir D]` | File/folder scan | `findings`, `apps`, `rule_errors`, `clamav`, `bench{...}`, `risk`, `scan_id` |
| `url URL... [--follow-redirects]` | URL analysis | `results[]{url,host,unicode_host,registrable_domain,score,verdict,redirects}`, `findings`, `risk` |
| `intel import --format urlhaus\|threatfox\|bazaar\|stix2\|misp\|list --file F --source S [--license L] [--reliability 0-100]` | Offline import | `records`, `skipped`, `payload_sha256` |
| `intel update --feed urlhaus\|threatfox\|bazaar [--auth-key-stdin]` | Online update | same as import |
| `intel lookup V` · `intel add …` · `intel delete --id` · `intel list [--q]` · `intel stats` | IOC management | |
| `judol add` (JSON on stdin) · `list [--q]` · `verify --id --analyst` · `delete --id --analyst` · `import --file CSV` · `check VALUE` | Gaming Watch admin & lookup | `classification`, `findings` |
| `case create --title --examiner` · `case list` · `case show ID` · `case note …` · `case timeline ID` | Forensic cases | |
| `evidence add --case --path [--device] [--method] --examiner` · `verify --id --examiner` · `analyze --id --examiner` | Evidence | `EvidenceRecord`, `VerifyResult{working_copy_intact,custody_chain}` |
| `history [--limit]` · `scan-get ID` | Stored scans | |
| `report --scan ID --format html\|json --out F [--sign]` | Report export (+ `F.sig.json`) | `path`, `signed` |
| `pqc new-seed` · `pqc pubkey` · `pqc sign --file --out` · `pqc verify --file --sig --pubkey` · `pqc encrypt --file --pubkey --out` · `pqc decrypt --file --out` | Quantum-ready crypto | |
| `audit-verify` · `audit-log [--limit]` | Tamper-evident audit log | `entries`, `intact`, `first_broken_seq` |
| `rules [--rules-dir]` | Compiled YARA-X rules | `count`, `files`, `rules`, `errors` |

## Finding object

```json
{
  "id": "9f2c…",                       // stable: sha256(engine|rule|subject)[:16]
  "title": "Accessibility service combined with screen overlay",
  "category": "banking_trojan",        // malware|spyware|stalkerware|ransomware|banking_trojan|rat|adware|pua|phishing|gambling|network_threat|permission|configuration|jailbreak|root|anomaly|integrity|limitation|other
  "severity": "HIGH",                  // CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL|NOT_ACCESSIBLE
  "confidence": "MEDIUM",              // CONFIRMED|HIGH|MEDIUM|LOW  (independent of severity)
  "engine": "permission-audit",        // yara-x|intel|gaming-watch|url-heuristics|shield|apk|clamav|argent-ai|…
  "rule": "AD-PERM-001",
  "subject": {"kind": "package", "name": "com.example", "path": null, "sha256": "…"},
  "evidence": ["accessibility service declared in manifest", "android.permission.SYSTEM_ALERT_WINDOW requested"],
  "recommendation": "…"
}
```

## YARA-X rule metadata convention

`category`, `severity` (CRITICAL…INFORMATIONAL), `confidence` (CONFIRMED…LOW), `description`, `recommendation`. Rules without metadata default to `malware / INFORMATIONAL / LOW`. Admin rules go in `~/Library/Application Support/ArgentDefender/rules/*.yar`.

## Gaming Watch CSV

`domain,url,package_name,apk_hash,brand_alias,indicator_type,classification,evidence,source,confidence` — `indicator_type ∈ {domain,url,package,apk_hash,brand}`, `classification ∈ {CONFIRMED_INDICATOR,HIGH_RISK,SUSPECTED}`; CONFIRMED requires non-empty evidence and is reported as CONFIRMED only after an analyst runs `judol verify`.
