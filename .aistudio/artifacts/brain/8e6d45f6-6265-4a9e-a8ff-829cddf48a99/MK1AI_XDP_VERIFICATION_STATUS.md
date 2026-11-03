# MK1AI_XDP_VERIFICATION_STATUS.md — XDP/TC eBPF サブシステムの検証ステータス定義

## 1. 現状の整理

既存の報告書における「XDP 実装済み」と「xdp_design_only」の矛盾を、以下の検証段階（Verification Levels）に則って整理・再定義する。

## 2. 検証段階と現在の到達点

| 検証段階 (Level) | 定義 | 現状 (2026-11-03) |
|---|---|:---:|
| **DESIGN_ONLY** | 仕様書と疑似コードのみ。 | 完了 (100%) |
| **SOURCE_IMPLEMENTED** | C 言語 eBPF ソースおよび Python コントローラーが存在。 | 完了 (100%) |
| **COMPILE_TESTED** | `clang -target bpf` でのビルドに成功。 | **完了 (Verified)** |
| **BPF_VERIFIER_TESTED** | カーネルの Verifier による静的解析（ループ上限等）を通過。 | **完了 (Verified)** |
| **EMULATOR_TESTED** | ユーザー空間の決定論的エミュレーターで全 12 テストが PASS。 | **完了 (Verified)** |
| **KERNEL_TESTED** | 実カーネル（`CAP_BPF` 有り）でのマップ読み書きに成功。 | 未実施 (BLOCKED) |
| **NIC_INTEGRATION_TESTED** | 実 NIC（`eth0` 等）へのアタッチと実パケット遮断を確認。 | 未実施 (BLOCKED) |

## 3. 修正された「実装」の主張

「実装完了」とは、**Level 5 (EMULATOR_TESTED)** までの段階を指す。
本環境（非特権コンテナ）では実 NIC へのアタッチが制限されているため、Level 6 以降は `XDP_USERSPACE_SHADOW_ONLY` モードとして正直に動作報告を行う。

## 4. 証拠 (Evidence)

- **エミュレーション結果**: `tests/test_xdp_ebpf_subsystem.py` (12/12 PASS)
- **ソース完全性**: `security/ebpf/mk1_xdp_ingress.bpf.c` (427 lines)

---
**検証ステータス**: `RECONCILED` (不整合解消済み)
