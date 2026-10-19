# TrustWeave Protocol v1.0 Specification

## 版本信息

- **Protocol Version**: 1.0
- **Release Date**: 2026-10-19
- **Status**: Stable
- **Compatibility**: 向下相容保證

## 概述

TrustWeave Protocol v1.0 定義了供應鏈安全驗證的二進位格式、JSON Schema、編碼規則和版本相容性策略。本規格書旨在確保 Rust 總帳、Nim 政策矩陣、Lean 4 .olean 證書和 .twledger 憑證的二進位 Schema 徹底水泥化，確保未來的內部優化不會破壞下游驗證端。

## 1. 二進位 Bundle 格式

### 1.1 整體結構

`.twledger` 文件採用固定標頭 + 可變載荷的結構：

| Offset | Size | Type | Description |
|--------|------|------|-------------|
| 0 | 8 | bytes | Magic bytes: `TWLDGR01` (ASCII) |
| 8 | 8 | uint64 | JSON payload length, unsigned big-endian |
| 16 | 32 | bytes | SHA-256 of JSON payload |
| 48 | 32 | bytes | SHA-256 of the bound executable |
| 80 | 32 | bytes | Provenance root hash |
| 112 | 32 | bytes | Ed25519 public key |
| 144 | 64 | bytes | Ed25519 signature |
| 208 | variable | bytes | JSON payload (BUNDLE_PAYLOAD) |

**總標頭長度**: 208 bytes  
**最大載荷長度**: 512 MiB (536,870,912 bytes)

### 1.2 Magic Bytes

```rust
const MAGIC: &[u8; 8] = b"TWLDGR01";
```

驗證端必須首先檢查 magic bytes，任何不匹配都應被拒絕。

### 1.3 載荷長度編碼

- 8 字節，無符號大端序（big-endian）
- 必須 ≤ 512 MiB
- 必須匹配：`payload_len == bundle_size - HEADER_LEN`

### 1.4 雜湊值格式

所有雜湊值均為 32 字節的原始 SHA-256 輸出（非十六進制編碼）。

### 1.5 Ed25519 簽名格式

- 公鑰：32 字節原始 Ed25519 公鑰
- 簽名：64 字節原始 Ed25519 簽名
- 簽名覆蓋：`SIGNING_DOMAIN || payload_hash || artifact_hash || provenance_root`

### 1.6 簽名域分隔

```rust
const SIGNING_DOMAIN: &[u8] = b"TrustWeave.twledger.v1\0";
```

簽名消息構造：
```
message = SIGNING_DOMAIN (24 bytes)
        + payload_hash (32 bytes)
        + artifact_hash (32 bytes)
        + provenance_root (32 bytes)
        = 120 bytes total
```

## 2. JSON Payload Schema

### 2.1 BundlePayload 結構

```json
{
  "schema_version": 1,
  "engine_version": "0.1.0",
  "ledger": { /* DependencyLedger */ },
  "policy": { /* PolicyMatrix */ },
  "proof_certificate": "base64-encoded .olean bytes",
  "source_merkle_root": "hex-encoded SHA-256",
  "policy_sha256": "hex-encoded SHA-256",
  "proof_sha256": "hex-encoded SHA-256",
  "artifact_sha256": "hex-encoded SHA-256",
  "provenance_root": "hex-encoded SHA-256"
}
```

### 2.2 DependencyLedger Schema

```json
{
  "engine_version": "0.1.0",
  "root_hash": "hex-encoded SHA-256",
  "root_hash_algorithm": "sha256",
  "timestamp": 1234567890,
  "entries": {
    "normalized/path/to/file": {
      "path": "normalized/path/to/file",
      "sha256": "hex-encoded SHA-256",
      "blake3": "hex-encoded BLAKE3",
      "size": 12345,
      "modified": 1234567890
    }
  }
}
```

**重要約束**：
- `entries` 必須是 JSON 對象（鍵值對）
- 鍵為歸一化路徑，值為 LedgerEntry
- `path` 字段必須與鍵完全匹配
- `sha256` 和 `blake3` 必須是 64 字符的十六進制字符串
- `root_hash_algorithm` 必須為 `"sha256"`（v1.0 僅支持 SHA-256）

### 2.3 PolicyMatrix Schema

```json
{
  "name": "Policy Name",
  "strictMode": true,
  "rules": [
    {
      "pattern": "dependency-name",
      "allowed": true,
      "source": "crates.io|npm|pypi|*",
      "versionConstraint": ">=1.0.0|*"
    }
  ],
  "constraints": [
    {
      "name": "constraint-name",
      "value": "constraint-value"
    }
  ]
}
```

**必填字段**：
- `name`: 字符串，政策名稱
- `strictMode`: 布爾值，嚴格模式開關
- `rules`: 數組，依賴規則列表
- `constraints`: 數組，全局約束列表

### 2.4 Proof Certificate

- `proof_certificate`: Base64 編碼的 Lean 4 .olean 文件內容
- 必須以 `olean` magic bytes 開頭
- 必須包含 Lean 4.35.0 版本標識

### 2.5 雜湊值編碼

所有十六進制雜湊值：
- 小寫字母
- 64 字符長度（SHA-256 的 32 字節）
- 無前綴（如 `0x`）

## 3. Merkle-DAG 構造規則

### 3.1 Leaf 節點編碼

每個文件條目編碼為：

```
leaf = 0x00
      + path_length (8 bytes, big-endian)
      + path_bytes
      + sha256_bytes (32 bytes)
sha256(leaf) = leaf_hash
```

### 3.2 Internal 節點編碼

內部節點（兩個子節點的合併）：

```
node = 0x01
      + left_hash (32 bytes)
      + right_hash (32 bytes)
sha256(node) = node_hash
```

對於奇數個葉子節點，最後一個節點與自身合併。

### 3.3 Root 節點編碼

Root 節點（用於 provenance root）：

```
root = 0x03
      + source_merkle_root (32 bytes)
      + policy_hash (32 bytes)
      + proof_hash (32 bytes)
      + artifact_hash (32 bytes)
sha256(root) = provenance_root
```

### 3.4 空樹處理

如果總帳為空（無文件），根雜湊為：

```
sha256([0x02]) = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
```

## 4. 驗證流程

### 4.1 Bundle 驗證步驟

1. **驗證 Magic Bytes**
   - 檢查前 8 字節是否為 `TWLDGR01`
   - 失敗則拒絕

2. **驗證載荷長度**
   - 讀取 8 字節大端序整數
   - 檢查 ≤ 512 MiB
   - 檢查 `payload_len == bundle_size - 208`
   - 失敗則拒絕

3. **驗證載荷雜湊**
   - 計算 SHA-256(payload_bytes)
   - 與標頭中的 payload_hash 比較
   - 失敗則拒絕

4. **驗證可執行文件綁定**
   - 計算當前可執行文件的 SHA-256
   - 與標頭中的 artifact_hash 比較
   - 失敗則拒絕

5. **驗證簽名**
   - 構造簽名消息：`SIGNING_DOMAIN || payload_hash || artifact_hash || provenance_root`
   - 使用 Ed25519 驗證簽名
   - 公鑰必須與信任的公鑰匹配
   - 失敗則拒絕

6. **驗證 JSON Schema**
   - 解析 JSON payload
   - 驗證所有必填字段存在
   - 驗證字段類型正確
   - 失敗則拒絕

7. **驗證 Ledger 完整性**
   - 重新計算總帳的 root_hash
   - 與 payload 中的 root_hash 比較
   - 失敗則拒絕

8. **驗證 Policy Matrix**
   - 驗證政策矩陣結構正確
   - 檢查所有規則字段完整
   - 失敗則拒絕

9. **驗證 Lean 4 證書**
   - 檢查 proof_certificate 以 `olean` 開頭
   - 提取並驗證 Lean 版本為 4.35.0
   - 失敗則拒絕

10. **驗證 Provenance Root**
    - 重新計算 provenance_root
    - 與標頭和 payload 中的 provenance_root 比較
    - 失敗則拒絕

### 4.2 Trust Anchor

驗證端必須：
- 使用獨立信任的公鑰文件（不能信任 bundle 中嵌入的公鑰）
- 公鑰文件必須通過安全渠道分發
- 信任錨的建立超出本協議範圍

## 5. 版本相容性策略

### 5.1 向下相容保證

**協議 v1.0 保證**：
- Magic bytes 永遠為 `TWLDGR01`
- 標頭長度永遠為 208 字節
- 簽名域分隔不變
- JSON schema 向下相容（新字段可選）
- 雜湊算法固定為 SHA-256

**未來版本**：
- 可能增加新的可選字段到 JSON payload
- 可能增加新的雜湊算法（通過 `root_hash_algorithm` 標識）
- 可能增加新的證書格式（通過 schema_version 標識）
- 但 v1.0 驗證端必須能夠驗證未來版本生成的 bundle（只要 schema_version=1）

### 5.2 版本識別

- `schema_version`: JSON payload 中的整數，指示 payload schema 版本
- `engine_version`: 字符串，指示生成 bundle 的引擎版本
- 未來版本可能引入新的 schema_version，但 v1.0 驗證端只接受 schema_version=1

### 5.3 升級路徑

當升級到協議 v2.0：
1. 增加 schema_version=2
2. 可能更改標頭結構（通過 magic bytes 區分）
3. v1.0 驗證端繼續支持 v1.0 bundle
4. v2.0 驗證端同時支持 v1.0 和 v2.0 bundle

## 6. 安全考慮

### 6.1 密鑰管理

- 種子密鑰必須是原始 32 字節 Ed25519 種子
- 必須通過安全方式保護（如硬件安全模組 HSM）
- 永遠不要將種子密鑰編碼為可讀格式存儲

### 6.2 簽名重放攻擊防護

- 簽名綁定到特定的可執行文件雜湊
- 簽名綁定到特定的 provenance root
- 攻擊者無法將簽名重用到不同的可執行文件

### 6.3 時間戳攻擊防護

- 總帳中的 `timestamp` 字段僅為描述性元數據
- 不參與任何雜湊計算
- 攻擊者無法通過修改時間戳來繞過驗證

### 6.4 路徑遍歷防護

- 所有路徑必須歸一化（使用 `/` 分隔符）
- 驗證端必須拒絕包含 `..` 的路徑
- 驗證端必須拒絕絕對路徑

## 7. 實現要求

### 7.1 Rust 實現

- 使用 `ring` 庫進行 Ed25519 簽名驗證
- 使用 `sha2` 庫進行 SHA-256 雜湊
- 使用 `serde` 進行 JSON 序列化/反序列化
- 嚴格遵循本規格書的字節順序和編碼規則

### 7.2 Nim 實現

- 使用標準庫的 `sha256` 模組
- 使用 `json` 模組進行 JSON 解析
- Ed25519 簽名可能需要外部庫

### 7.3 Forth 實現

- 實現 `sha256` 原語（接收地址、長度、輸出地址）
- 實現 `ed25519-verify` 原語（接收消息、公鑰、簽名）
- 實現 `tw-allow-image` 和 `tw-refuse-image` 原語
- 簽名驗證失敗必須調用 `tw-refuse-image`

## 8. 測試向量

### 8.1 最小 Bundle

```
Magic: TWLDGR01
Payload length: 256
Payload hash: (example)
Artifact hash: (example)
Provenance root: (example)
Public key: (example)
Signature: (example)
Payload: { ... }
```

### 8.2 完整 Bundle

完整測試向量見 `tests/protocol_test_vectors.json`。

## 9. 參考實現

- Rust: `crates/tw-engine/src/bundle.rs`
- Nim: `parsers/tw_parser.nim`
- Forth: `forth/tinyverify.fs`

## 10. 變更日誌

### v1.0 (2026-10-19)
- 初始穩定版本
- 定義二進位 bundle 格式
- 定義 JSON schema
- 定義 Merkle-DAG 構造規則
- 定義驗證流程
- 建立向下相容保證

## 11. 許可證

本規格書採用 MIT OR Apache-2.0 雙重許可證，與 TrustWeave 項目一致。

## 12. 聯繫方式

- 項目倉庫: https://github.com/trustweave/trustweave
- 安全問題: security@trustweave.org
