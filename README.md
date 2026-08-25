# Copyright (c) 2026 barbiegivesoutcookies

# IocEnrichmentEngine

**Standalone Threat Intelligence Lookup Tool**

A high-performance, cross-platform command-line threat enrichment engine engineered in C# and .NET 10.0. The tool performs asynchronous external reputation lookups for key security indicators (Cryptographic File Hashes, IPv4 Addresses, and FQDN Hostnames) by querying authoritative cyber threat intelligence APIs natively.

---

## Integration & Telemetry Framework

| Indicator Target | Data Source | Endpoint | Authentication |
|---|---|---|---|
| File Hashes | VirusTotal v3 API | `https://www.virustotal.com/api/v3/files/{hash}` | `x-apikey` header (`VT_API_KEY`) |
| File Hashes | VirusTotal v3 API (same endpoint, unauthenticated) | `https://www.virustotal.com/api/v3/files/{hash}` | Anonymous fallback on HTTP 401/429 |
| IP Addresses | ipapi.co Standard API | `https://ipapi.co/{ip}/json/` | Keyless (always-on geolocation context) |
| IP Addresses | AbuseIPDB v2 API | `https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90` | `Key` header (`ABUSEIPDB_API_KEY`); skipped entirely if unset |
| Domain Names | Live local DNS Resolution | OS resolver (`System.Net.Dns`) — A/AAAA records | None |
| Domain Names | abuse.ch URLhaus Host API | `POST https://urlhaus-api.abuse.ch/v1/host/` (`host={domain}` form field) | Optional `Auth-Key` header (`URLHAUS_AUTH_KEY`); abuse.ch now rejects keyless calls with HTTP 401 |

No invented or unverified third-party endpoints are used anywhere in the pipeline. Anonymous mode always targets the same documented service unauthenticated, or omits that data source entirely.

---

## Core Architectural Features

- **Asynchronous Execution Pipeline:** Uses modern non-blocking `System.Net.Http` calls to fire off concurrent web queries efficiently without stalling system resources.
- **Independent Credential Fallback Manager:** Evaluates and applies API authentication strings separately. If an API key is missing or encounters a rate-limit event, the routine degrades gracefully to anonymous public feeds without crashing other concurrent pipeline tasks.
- **Zero-Dependency Native Footprint:** Built exclusively using the native .NET Base Class Library (BCL) and compiled using .NET 10 optimization standards. Does not require external packages, scripts, or wrappers.
- **Strict Input Sanitization:** Performs validation checks (regex matching exactly 64 hex characters, `IPAddress.TryParse`, FQDN label validation) *prior* to initiating network routines to eliminate malformed API overhead.
- **Contained Failure Semantics:** All HTTP calls are wrapped in exception boundaries covering connection faults, DNS failures, timeouts, non-2xx responses, and malformed JSON. The process never crashes; every failure degrades to a logged error message and exit code `3`.
- **Standardized Console Output:** Fixed-layout ASCII report blocks with color severity signaling — red for malicious findings, yellow for suspicious/inconclusive results, green for clean verdicts.

---

## Secure Credential Management & Environment Keys

Keys are passed exclusively through environment variables. No tokens are hardcoded in source control.

| Variable | Purpose |
|---|---|
| `VT_API_KEY` | Unlocks authenticated premium file reputation data streams via VirusTotal. |
| `ABUSEIPDB_API_KEY` | Queries threat confidence indices and historic incident counts via AbuseIPDB. |
| `URLHAUS_AUTH_KEY` | Supplies the free registered abuse.ch `Auth-Key` required by URLhaus host lookups. |

Each credential is evaluated independently — one being present or absent never affects the other routines.

### Configuration Commands

Windows Command Prompt:

```bat
setx VT_API_KEY "your_key"
setx ABUSEIPDB_API_KEY "your_key"
setx URLHAUS_AUTH_KEY "your_key"
```

Linux / Kali Terminal:

```bash
export VT_API_KEY="your_key"
export ABUSEIPDB_API_KEY="your_key"
export URLHAUS_AUTH_KEY="your_key"
```

Per-routine authentication state is printed at runtime, e.g.:

```
[+] Hash Auth: VIRUSTOTAL (authenticated)
[+] Hash Auth: ANONYMOUS FEED FALLBACK
[+] IP Auth: ABUSEIPDB (authenticated)
[+] IP Auth: ANONYMOUS (AbuseIPDB skipped, geolocation only)
```

---

## Syntax, Exit Codes & Usage Specifications

### Command Execution Blueprint

```
IocEnrichmentEngine <type_flag> <indicator_value>
```

### Detailed Flags Module

| Flag | Target |
|---|---|
| `--hash` | 64-character SHA-256 string footprint. |
| `--ip` | IPv4 networking address. |
| `--domain` | Fully Qualified Domain Name. |

### Examples

```
IocEnrichmentEngine --hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
IocEnrichmentEngine --ip 8.8.8.8
IocEnrichmentEngine --domain wikipedia.org
```

### Operational Exit Codes Grid

| Code | Classification | Condition |
|---|---|---|
| `0` | Analysis Complete | Clean indicator signature verified. |
| `1` | High-Risk Hit | Malicious match identified inside active threat databases. |
| `2` | Input Error | Invalid syntax, missing arguments, or bad indicator alignment. |
| `3` | Integration Error | API timeout, network failure, or malformed JSON payload response. |

Precedence: exit code `1` overrides `3` when malicious findings coexist with partial enrichment errors.

### Sample Report Block

```
 ----------------------------------------------------------------
  DOMAIN ROUTINE - LIVE DNS RESOLUTION + URLHAUS CROSS-REFERENCE
 ----------------------------------------------------------------
 [+] Domain Auth: ANONYMOUS FEED FALLBACK
 [i] Output reflects live DNS A/AAAA resolution and abuse.ch URLhaus activity; passive-DNS history is out of scope.
 [-] Live DNS resolution (A/AAAA records):
     A    : 185.15.58.224
 [!] abuse.ch URLhaus refused anonymous access (HTTP 401): the feed requires a free registered Auth-Key - set URLHAUS_AUTH_KEY for domain feed lookups.

 ----------------------------------------------------------------
  SUMMARY
 ----------------------------------------------------------------
 [+] ANALYSIS RESULT: NO HIGH-RISK FINDINGS (exit code 0).
```

---

## Cross-Platform Compilation Blueprint

Requires the .NET 10 SDK. Both commands produce an isolated, self-contained single-file binary embedding its own runtime environment. Run sequentially — concurrent publishes race on the restore assets file.

Cross-compiling for x64 Windows Architectures (.exe):

```
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true -p:DebugType=embedded -o publish/win-x64
```

Cross-compiling for x64 Linux / Kali Linux Environments:

```
dotnet publish -c Release -r linux-x64 --self-contained true -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true -p:DebugType=embedded -o publish/linux-x64
```

Artifacts:

- `publish/win-x64/IocEnrichmentEngine.exe`
- `publish/linux-x64/IocEnrichmentEngine` (apply `chmod +x` before execution)

---

## License

Copyright (c) 2026 barbiegivesoutcookies. All rights reserved.
