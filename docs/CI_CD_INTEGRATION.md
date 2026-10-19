# TrustWeave CI/CD Integration Guide

## 概述

TrustWeave CI/CD 集成提供了自動化的供應鏈安全驗證閘門，確保所有通過的代碼和依賴都經過嚴格的確定性掃描、政策合規檢查、數學證明驗證和數位簽章保護。

## 架構設計

### 五階段驗證流程

1. **Phase 1: 確定性源碼掃描**
   - 掃描整個專案目錄
   - 生成包含所有文件的 SHA-256 和 BLAKE3 雜湊值的總帳
   - 構建 Merkle-DAG 確保路徑敏感的確定性

2. **Phase 2: 政策合規檢查**
   - 使用 Nim 解析器驗證依賴聲明
   - 檢查 Cargo.toml、package.json、requirements.txt 等配置文件
   - 執行政策矩陣 DSL 驗證

3. **Phase 3: Lean 4 數學證明**
   - 編譯 TrustWeave.lean 數學規範
   - 生成 .olean 證明證書
   - 驗證 Lean 版本鎖定（4.35.0）

4. **Phase 4: Rust 安全檢查**
   - 執行 clippy 靜態分析
   - 檢查代碼格式（rustfmt）
   - 所有警告都被視為錯誤

5. **Phase 5: 完整性驗證**
   - 執行完整測試套件
   - Fail-Fast 機制：任何失敗立即終止 CI 流程

## GitHub Actions 使用

### 方式一：使用預配置的 Workflow

將 `.github/workflows/trustweave-gatekeeper.yml` 添加到您的倉庫即可自動啟用。

### 方式二：使用複合 Action

在您現有的 workflow 中添加 TrustWeave 掃描步驟：

```yaml
name: Your CI Pipeline

on:
  pull_request:
    branches: [main]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: TrustWeave Supply Chain Scan
        uses: ./trustweave/.github/actions/trustweave-scan
        with:
          root: '.'
          policy-file: 'tw-policy.json'
          fail-on-violation: 'true'
```

### 輸出變量

Action 提供以下輸出變量供後續步驟使用：

- `ledger-hash`: 生成的依賴總帳的 SHA-256 雜湊值
- `policy-status`: 政策合規狀態（pass/fail/skipped）
- `proof-status`: Lean 4 證明編譯狀態（pass/fail/skipped）

## GitLab CI 使用

將 `.gitlab-ci.yml` 添加到您的倉庫即可自動啟用。

### 階段執行順序

1. `trustweave-verify` - 所有 TrustWeave 驗證階段
2. `build` - 僅在 TrustWeave 驗證通過後執行
3. `test` - 完整測試套件
4. `deploy` - 手動觸發的部署階段，生成簽名的 .twledger bundle

### Fail-Fast 機制

設置 `TRUSTWEAVE_FAIL_FAST: "true"` 變量以啟用失敗時立即終止。

## 自定義政策配置

創建 `tw-policy.json` 文件定義您的供應鏈安全政策：

```json
{
  "name": "Your Project Policy",
  "strictMode": true,
  "rules": [
    {
      "pattern": "serde",
      "allowed": true,
      "source": "crates.io",
      "versionConstraint": ">=1.0.0"
    },
    {
      "pattern": "unknown-dependency",
      "allowed": false,
      "source": "*",
      "versionConstraint": "*"
    }
  ],
  "constraints": [
    {
      "name": "max-dependencies",
      "value": "100"
    },
    {
      "name": "allow-dev-dependencies",
      "value": "false"
    }
  ]
}
```

## 簽名密鑰管理

### 生成簽名密鑰對

```bash
# 生成 Ed25519 種子密鑰
cargo run --package tw-engine -- keygen --seed ~/.trustweave-keys/signer.seed --public ~/.trustweave-keys/signer.pub
```

### 保護密鑰

- **種子密鑰 (.seed)**: 必須保存在安全的位置，僅用於簽名
- **公鑰 (.pub)**: 可以公開，用於驗證簽名
- **CI/CD 環境**: 使用 GitHub Secrets 或 GitLab CI/CD Variables 存儲種子密鑰

### 在 CI 中使用密鑰

**GitHub Actions:**
```yaml
- name: Create Signed Bundle
  env:
    TRUSTWEAVE_SIGNING_SEED: ${{ secrets.TRUSTWEAVE_SIGNING_SEED }}
  run: |
    cargo run --package tw-engine -- bundle \
      --root . \
      --policy tw-policy.json \
      --proof specs/TrustWeave.olean \
      --artifact target/release/your-app \
      --seed <(echo "$TRUSTWEAVE_SIGNING_SEED") \
      --output dist/your-app.twledger
```

**GitLab CI:**
```yaml
deploy:signed-bundle:
  variables:
    TRUSTWEAVE_SIGNING_SEED: $TRUSTWEAVE_SIGNING_SEED
  script:
    - cargo run --package tw-engine -- bundle \
      --root . \
      --policy tw-policy.json \
      --proof specs/TrustWeave.olean \
      --artifact target/release/your-app \
      --seed <(echo "$TRUSTWEAVE_SIGNING_SEED") \
      --output dist/your-app.twledger
```

## 驗證簽名的 Bundle

在部署環境或終端用戶端驗證簽名：

```bash
cargo run --package tw-engine -- verify \
  --bundle dist/your-app.twledger \
  --trusted-key ~/.trustweave-keys/signer.pub \
  --artifact /path/to/deployed/your-app
```

## 故障排除

### TrustWeave 驗證失敗

1. 檢查 `tw-ledger.json` 確認哪些文件被標記為已更改
2. 驗證 `tw-policy.json` 中的政策規則是否過於嚴格
3. 確認 Lean 4 版本鎖定為 4.35.0
4. 檢查 Rust clippy 警告並修復

### 政策違規

修改 `tw-policy.json` 以允許必要的依賴，或者更新依賴版本以符合政策。

### Lean 4 編譯失敗

確保 `specs/TrustWeave.lean` 文件存在且語法正確，Lean 4.35.0 已正確安裝。

## 最佳實踐

1. **分支保護**: 設置分支保護規則，要求 TrustWeave CI 通過才能合併
2. **定期審查**: 定期審查並更新政策規則
3. **密鑰輪換**: 定期輪換簽名密鑰
4. **監控警報**: 設置 CI 失敗警報通知
5. **本地測試**: 在推送前本地運行 `cargo test --workspace` 和 `nim check parsers/tw_parser.nim`

## 安全考慮

- CI 環境中的種子密鑰必須使用安全的 Secrets 管理系統
- 永遠不要將種子密鑰提交到版本控制
- .twledger bundle 應該與可執行文件一起分發
- 驗證端必須使用獨立信任的公鑰，不要信任 bundle 中嵌入的公鑰

## 性能優化

- 使用 CI 緩存加速構建（Cargo registry、Cargo index、target 目錄）
- 並行執行 TrustWeave 驗證階段
- 對大型倉庫，考慮增量掃描或只掃描關鍵目錄

## 進階配置

### 自定義掃描目錄

```yaml
- name: TrustWeave Scan
  uses: ./trustweave/.github/actions/trustweave-scan
  with:
    root: 'src/'  # 只掃描 src 目錄
```

### 禁用 Fail-Fast

```yaml
- name: TrustWeave Scan
  uses: ./trustweave/.github/actions/trustweave-scan
  with:
    fail-on-violation: 'false'  # 允許政策違警但記錄
```

### 多矩陣構建

TrustWeave gatekeeper workflow 已經配置了多矩陣構建（Ubuntu 和 Windows），確保跨平台一致性。

## 參考文檔

- [TrustWeave README](../README.md)
- [TrustWeave Protocol v1.0 Specification](PROTOCOL_V1.md)
- [Nim Parser Documentation](../parsers/README.md)
- [Lean 4 Proof Specification](../specs/README.md)
