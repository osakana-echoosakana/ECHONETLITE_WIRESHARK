# ECHONET Lite Wireshark ディセクタ（Lua プラグイン）

Wireshark / tshark で ECHONET Lite の電文を解析するための Lua プラグインです。
ビルド不要で、ファイルを 1 つコピーするだけで使えます。

## 対応内容

| 項目 | 内容 |
|---|---|
| トランスポート | UDP 3610（設定で変更可）、他ポートのヒューリスティック検出（既定 OFF） |
| ヘッダ | EHD1 / EHD2（形式1・形式2）/ TID |
| EOJ | SEOJ / DEOJ をクラスグループ・クラス・インスタンスに分解し、クラス名を表示 |
| ESV | 全 ESV（SetI, SetC, Get, INF_REQ, SetGet, 各 _Res, INF, INFC, INFC_Res, 各 _SNA）を名称付きで表示 |
| SetGet | SetGet / SetGet_Res / SetGet_SNA の OPCSet・OPCGet 2 区画を個別に解析 |
| プロパティ | OPC / EPC / PDC / EDT。EPC 名称はクラスごとの表 → スーパークラスの順で引く |
| 値の解釈 | 動作状態(0x80)、設置場所(0x81)、規格Version(0x82)、異常発生状態(0x88)、メーカコード(0x8A)、プロパティマップ(0x9D/0x9E/0x9F、リスト形式・ビットマップ形式とも)、インスタンスリスト(0xD5/0xD6)、クラスリスト(0xD7)、瞬時電力/積算電力(0x84/0x85) ほか |
| クラス固有 | 家庭用エアコン、温度/湿度/照度/CO2/人体検知センサ、住宅用太陽光発電、蓄電池、EV充放電器、低圧スマート電力量メータ、一般照明、電気錠、電気温水器 などの主要 EPC |
| エキスパート情報 | 短すぎるフレーム、PDC と実データの不一致、未知の ESV、末尾の余剰バイト、SNA 応答 |

Info 列には `Get_Res 013001 -> 05FF01 TID=4 EPC[80,B0,B3]` のように要約が表示されます。

## インストール

### Windows（インストーラー）

1. [Releases](https://github.com/osakana-echoosakana/ECHONETLITE_WIRESHARK/releases) から
   `echonet-lite-wireshark-setup-<バージョン>.exe` をダウンロードして実行します。
   管理者権限は不要です。
2. `echonet_lite.lua` が `%APPDATA%\Wireshark\plugins\` にコピーされます。
3. Wireshark を再起動します（起動中なら **解析 → Lua プラグインを再読み込み**、`Ctrl+Shift+L` でも可）。

アンインストールは「設定 → アプリ」（または「プログラムと機能」）の
「ECHONET Lite Wireshark Dissector」から行えます。サイレントインストールは `/S` を付けて実行します。

> 署名していない exe のため、初回実行時に Windows SmartScreen の警告が出ることがあります。
> 「詳細情報 → 実行」で続行してください。

### 手動インストール（Windows / macOS / Linux）

1. `echonet_lite.lua` をダウンロードします。
2. Wireshark を起動し、**ヘルプ → Wireshark について → フォルダ** タブを開き、
   「**個人 Lua プラグイン**（Personal Lua Plugins）」のパスを確認します。代表的な場所は次の通りです。
   - Windows: `%APPDATA%\Wireshark\plugins\`
   - macOS / Linux: `~/.local/lib/wireshark/plugins/`
3. そのフォルダ（無ければ作成）に `echonet_lite.lua` をコピーします。
4. Wireshark を再起動します（または **解析 → Lua プラグインを再読み込み**、`Ctrl+Shift+L`）。
5. **ヘルプ → Wireshark について → プラグイン** に `echonet_lite.lua` が出ていれば成功です。

tshark で一時的に使う場合は次のように指定できます。

```sh
tshark -X lua_script:echonet_lite.lua -r capture.pcap
```

> Linux で root 権限のまま tshark/Wireshark を実行すると、セキュリティ上の理由で
> 個人 Lua スクリプトが読み込まれません。一般ユーザで実行してください
> （キャプチャ権限は `wireshark` グループ等で付与）。

## 使い方

- キャプチャフィルタ例: `udp port 3610`
- 表示フィルタ例:

| フィルタ | 意味 |
|---|---|
| `echonetlite` | ECHONET Lite の全フレーム |
| `echonetlite.esv == 0x72` | Get_Res のみ |
| `echonetlite.esv >= 0x50 && echonetlite.esv <= 0x5F` | 不可応答 (SNA) のみ |
| `echonetlite.seoj == 0x013001` | 送信元がエアコン #1 |
| `echonetlite.eoj.class == 0x0288` | 低圧スマートメータが関係するフレーム |
| `echonetlite.epc == 0x80` | 動作状態を含むフレーム |
| `echonetlite.tid == 5` | TID で要求と応答を対応付け |

### 設定

**編集 → 設定 → Protocols → ECHONET Lite** で以下を変更できます。

- **UDP port**: 既定 3610
- **Heuristic detection on other UDP ports**: 3610 以外のポートでも EHD1=0x10 / EHD2=0x81・0x82 のパケットを自動検出（既定 OFF）

任意のポートを一時的に ECHONET Lite として解析したい場合は、パケットを右クリック →
**Decode As…** で「ECHONET Lite」を選んでも構いません。

## サンプルとテスト

- `samples/echonet_lite_sample.pcap`: 動作確認用のサンプル（22 フレーム）。
  ノード探索、インスタンスリスト通知、プロパティマップ（リスト／ビットマップ）、エアコンの状態取得、
  SetC、SetGet、Get_SNA、スマートメータ、INFC/INFC_Res、形式2、壊れたフレームを含みます。
- `tools/make_sample_pcap.py`: 上記サンプルを生成する Python スクリプト（外部ライブラリ不要）。

```sh
python3 tools/make_sample_pcap.py samples/echonet_lite_sample.pcap
tshark -X lua_script:echonet_lite.lua -r samples/echonet_lite_sample.pcap -O echonetlite
```

Wireshark 4.2.2 (Lua 5.2) で動作確認済みです。Wireshark 3.x 以降であれば動作する想定です。

## インストーラーのビルド

`installer/echonet_lite_installer.nsi`（NSIS 3）から作成します。Linux でもビルドできます。

```sh
sudo apt-get install nsis
makensis -DVERSION=1.0.0 installer/echonet_lite_installer.nsi   # dist/ に exe が出力されます
```

GitHub Actions（`.github/workflows/build-installer.yml`）が push・PR ごとに exe をビルドし、
Artifacts に保存します。`v1.0.0` のようなタグを push すると、exe と `echonet_lite.lua` を添付した
Release が自動で作成されます。

## 拡張方法

名称や値の解釈は `echonet_lite.lua` 内の表で管理しています。

- クラス名を追加: `CLASS_NAMES` に `[0xGGCC] = "名称"`
- クラス固有 EPC 名を追加: `CLASS_EPC_NAMES[0xGGCC]` に `[0xEP] = "名称"`
- 値の解釈を追加: `decode_value()` 内に条件を追加

名称は ECHONET Lite 規格書および APPENDIX「ECHONET 機器オブジェクト詳細規定」の英語表記に準じています。
収録していないクラスや EPC は「Unknown」と表示され、EDT は 16 進数で表示されます。

## 制限事項

- TCP 上の ECHONET Lite は未対応です（ヘッダに長さが無いため、1 セグメント 1 電文の前提でも誤判定しやすいため）。
- クラス・EPC の名称は主要なもののみ収録しています。全クラスの網羅はしていません。
- 形式2（任意電文形式）はペイロードを 16 進表示するのみです。

## ライセンス

MIT
