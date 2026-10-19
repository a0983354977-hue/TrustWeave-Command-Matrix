# TrustWeave Command Matrix (TCM)

> **Local-First Cyber Defense & Threat Hunting Matrix** — 100% on-device, zero data leakage.

TrustWeave Command Matrix is a high-performance, privacy-preserving cybersecurity toolkit designed for modern threat hunting, binary analysis, and provenance-backed defense. Built with pure Rust and Tauri, it guarantees that no data ever leaves your machine.

---

## 🛡️ Core Features

### Internal Defense (Merkle-DAG Ledger)
- **Merkle-DAG Provenance**: Cryptographically binds source trees, policies, and artifacts.
- **Provenance Credentials**: Ed25519-signed `.twledger` bundles that verify build integrity.
- **Policy-as-Code**: Nim-compiled policy DSL that enforces rules at compile time.

### Threat Hunting (Pure-Rust yara-x Engine)
- **yara-x Integration**: Leverages the cutting-edge Rust YARA-X engine for lightning-fast binary analysis.
- **On-Device Scanning**: Scan binaries, memory dumps, and files without cloud dependencies.
- **Custom Rule DSL**: Write and compile threat-hunting rules in a safe, declarative language.

### Zero Data Leakage
- **100% Local Processing**: All analysis happens on your machine.
- **No Telemetry**: No network calls, no data exfiltration, no cloud dependencies.
- **Air-Gap Ready**: Designed for secure, disconnected environments.

---

## 🛠️ Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| **Backend** | Rust (Workspace) | Core engine, crypto, file traversal |
| **Desktop** | Tauri 2 | Lightweight, secure desktop shell |
| **Threat Hunting** | yara-x (Rust) | High-performance pattern matching |
| **Provenance** | Merkle-DAG + Ed25519 | Cryptographic integrity & signing |
| **Policy DSL** | Nim | Compile-time policy compilation |
| **Formal Verification** | Lean 4 | Machine-checked security proofs |

---

## 🚀 Quick Start

### Prerequisites
- **Rust**: 1.80+ (via [rustup](https://rustup.rs))
- **Nim**: 2+ (for policy DSL compilation)
- **Lean 4**: 4.35.0 (pinned in `lean-toolchain`)
- **Gforth**: 0.7+ (for host sandbox testing)

### Build Instructions

#### 1. Build the Core Engine
```bash
cargo build --release -p tw-engine
```

#### 2. Compile the Policy DSL
```bash
nim c -r parsers/tw_policy_dsl.nim
```

#### 3. Build the Desktop App (Tauri)
```bash
cd apps/tcm-desktop
cargo build --release
# Or with the YARA scanner feature:
cargo build --release --features yara-scanner
```

#### 4. Generate a Signed Provenance Bundle
```bash
# Generate signing keys
cargo run -p tw-engine -- keygen --seed signer.seed --public signer.pub

# Compile the Lean proof
lean -o specs/TrustWeave.olean specs/TrustWeave.lean

# Create the bundle
cargo run -p tw-engine -- bundle \
  --root . \
  --policy tw-policy.json \
  --proof specs/TrustWeave.olean \
  --artifact path/to/your/built-program.exe \
  --seed signer.seed \
  --output dist/program.twledger
```

---

## 📁 Project Structure

```
trustweave/
├── crates/                  # Core Rust libraries
│   └── tw-engine/           # Main engine (crypto, scanning, bundling)
├── apps/                    # Application frontends
│   ├── tcm-desktop/         # Tauri desktop shell
│   └── command-matrix/      # Web-based matrix UI
├── parsers/                 # Nim-based policy DSL
├── forth/                   # Forth endpoint verification
├── specs/                   # Formal Lean 4 proofs
├── tests/                   Integration & unit tests
└── docs/                    Documentation & design specs
```

---

## 📜 License

MIT OR Apache-2.0 — see [LICENSE](LICENSE) for details.

---

**Security is not a product, it's a process.** TrustWeave provides the tools; you provide the vigilance.