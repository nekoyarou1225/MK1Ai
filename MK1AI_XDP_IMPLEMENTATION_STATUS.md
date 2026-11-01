# MK1AI_XDP_IMPLEMENTATION_STATUS — 10-Point Granular XDP Implementation & Verification Status

## 1. 監査の目的

XDP（eXpress Data Path）に関して、「設計書の作成」と「実コードの実装・ビルド・検証」を混同しないよう、指定された10項目を個別に分離して現在のリポジトリの実態を監査した。

---

## 2. XDP 10項目ステータス一覧表

| # | 監査項目 | 現在のステータス | リポジトリ内の実態・技術的根拠 |
|---|---|---|---|
| 1 | **XDPの設計** | **DESIGN ONLY（設計書のみ存在・要修正点あり）** | `MK1AI_XDP_REDESIGN.md` および `MK1AI_XDP_ENFORCEMENT_MATRIX.md` にアーキテクチャとCコード案が記載されている。ただし、設計書内のCコード案には① Port 22/8006に対するSYN Floodレート制限バイパス、② IPv6 (`ETH_P_IPV6`) 未検査、③ IPv4フラグメント (`frag_off`) 未検査の3点の設計欠陥が残存している。 |
| 2 | **Cソースの存在** | **`NOT IMPLEMENTED`（0ファイル）** | リポジトリ内の全ファイルを走査した結果、`.bpf.c` ファイルは **1つも存在しない**（`security/ebpf/mk1_xdp_ingress.bpf.c` ディレクトリ・ファイルともに未作成）。現存するCソースは `mk1_memory_guard.c`、`mk1_panel.c`、`mk1_path_trust.c` の3ファイルのみであり、いずれもユーザー空間用である。 |
| 3 | **BPFプログラムのビルド** | **`NOT TESTED` / `NOT IMPLEMENTED`** | Cソースが存在せず、`Makefile` にも `clang -O2 -g -target bpf` 等のeBPFビルドターゲットは存在しないため、BPFオブジェクト（`.bpf.o`）のコンパイルは一度も実施されていない。 |
| 4 | **BPF verifierの確認** | **`NOT TESTED`** | コンパイル済み `.bpf.o` が存在せず、カーネルへのロード（`BPF_PROG_LOAD` システムコール）も未実施であるため、Linuxカーネル内BPF verifierによるループ有界性・ポインタ境界検査（`data + offset > data_end`）・スタックサイズ制限（512B）の通過確認は一切行われていない。 |
| 5 | **ローダーの存在** | **`NOT IMPLEMENTED`（0ファイル）** | `libbpf` ベースのCローダー、`ip link set dev <if> xdp obj ...` を呼び出すスクリプト、または `bcc`/`pyroute2`/`libbpf` を用いてBPFプログラムのロードとBPF Map（`blacklist_v4`, `syn_rate_map`, `xdp_events_rb` 等）のピン留め・更新を行うPython連携コードはリポジトリ内に存在しない。 |
| 6 | **実際のアタッチ** | **`NOT TESTED` / `NOT IMPLEMENTED`** | いかなるネットワークインターフェースに対してもXDPプログラム（`xdpdrv` / `xdpgeneric` / `xdpoffload`）およびTC（`clsact`）プログラムのアタッチは行われていない。 |
| 7 | **対象インターフェース** | **DESIGN ONLY（実コードは単一IFの `AF_PACKET` のみ）** | 設計書上は物理NIC（`eth0` / `ens*`）、ブリッジ（`vmbr0`）、WireGuard（`wg0` はL3のためTC ingressまたはpost-decryption）を対象としているが、現行の `airgap_ai_defender.py:5246` は単一の `interface` 引数に対して `raw_sock.bind((interface, 0))` で `AF_PACKET` ソケットをバインドするのみである。 |
| 8 | **Native XDPの動作** | **`NOT TESTED`** | 対応NICドライバ（`ixgbe`, `i40e`, `ice`, `mlx5`, `virtio_net` 等）上でのNative XDP（`XDP_FLAGS_DRV_MODE`）の動作検証は一切実施されていない。 |
| 9 | **実際のパケット検査** | **`NOT TESTED`（XDP層では未実施）** | 現在パケット検査を行っているのはユーザー空間のPython関数（`parse_packet_transport()`, `analyze_dpi_payload()`, `inspect_packet_pipeline()`）のみであり、カーネルXDPコンテキスト（`struct xdp_md *ctx`）でのパケット検査は一切実行されていない。 |
| 10 | **実際の遮断** | **`NOT IMPLEMENTED` / `NOT TESTED`** | カーネルXDP層での `XDP_DROP` によるパケット破棄は未実装である。また、現行のPythonキャプチャループ（`airgap_ai_defender.py:5245`）は `socket.AF_PACKET, socket.SOCK_RAW` によるクローン `sk_buff` の受動読み取りであり、Python側が `block=True` と判定してもカーネル内の元パケットは破棄されず、さらにKill SwitchもDry-Run（`_DRY_RUN = True`）に固定されているため、**実通信の遮断は行われない**。 |

---

## 3. 設計書（`MK1AI_XDP_REDESIGN.md`）内のCコード案に対する技術監査指摘

今後XDPを実装するにあたり、既存の `MK1AI_XDP_REDESIGN.md` に掲載されているドラフトCコードには以下の3点の欠陥があるため、そのまま実装してはならない：

1. **TCP SYNレート制限の前に管理ポート（Port 22 / 8006）を無条件 `XDP_PASS` している欠陥**
   - ドラフトコードでは、`if (dport == 22 || dport == 8006) return XDP_PASS;` がTCP SYNレート制限チェックよりも前に置かれている。このため、攻撃者が宛先ポート `22` または `8006` に対してSYN Flood攻撃を行った場合、XDPのレート制限マップを完全に素通りする。
2. **IPv6（`ETH_P_IPV6`）トラフィックの無検査通過**
   - ドラフトコードは `if (h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;` としており、IPv6パケットに対してブラックリスト照合もL4ポート検査も行っていない。LPM TrieマップをIPv4（`/32`）とIPv6（`/128`）の双方に対応させる必要がある。
3. **IPv4非先頭フラグメント（`frag_off & 0x1FFF != 0`）のL4誤解釈**
   - IPv4ヘッダの `frag_off` を検査せずに直後をTCP/UDPヘッダとしてパースしているため、非先頭フラグメントの先頭4バイトをポート番号と誤認する。XDP層では非先頭フラグメントを検知してレート制限またはDropする処理が必要である。
