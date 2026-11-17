# ECHONET Lite Wireshark ディセクタ（Lua プラグイン）

Wireshark / tshark で ECHONET Lite の電文を解析するための Lua プラグインです。
ビルド不要で、ファイルを 1 つコピーするだけで使えます。

エコーネットコンソーシアムが公開している **Machine Readable Appendix（MRA）** を所定のフォルダに置くと、
起動時に読み込み、APPENDIX「ECHONET 機器オブジェクト詳細規定」**Release A〜R** のクラス名・プロパティ名・
値の意味を表示します。表示は**日本語（既定）と英語**を切り替えられます。

> MRA はこのプラグインやインストーラーには**含まれていません**。各自でエコーネットコンソーシアムから入手してください
> （[MRA の配置](#mra-の配置)）。MRA が無い場合は、内蔵の簡易表（主要なクラス名・プロパティ名）で表示します。

## 対応内容

| 項目 | 内容 |
|---|---|
| トランスポート | UDP 3610（設定で変更可）、他ポートのヒューリスティック検出（既定 OFF） |
| ヘッダ | EHD1 / EHD2（形式1・形式2）/ TID |
| EOJ | SEOJ / DEOJ をクラスグループ・クラス・インスタンスに分解し、クラス名を表示 |
| ESV | 全 ESV（SetI, SetC, Get, INF_REQ, SetGet, 各 _Res, INF, INFC, INFC_Res, 各 _SNA）を名称付きで表示 |
| SetGet | SetGet / SetGet_Res / SetGet_SNA の OPCSet・OPCGet 2 区画を個別に解析 |
| プロパティ | OPC / EPC / PDC / EDT。EPC 名称はクラス固有 → スーパークラスの順で引く |
| MRA 読み込み時 | MRA に定義されている全クラス・全プロパティ（MRA v1.3.1 では機器オブジェクト 55 クラス、ノードプロファイル、スーパークラスの計 982 定義）の名称を表示 |
| 値の解釈（MRA 読み込み時） | MRA のデータ定義（数値と単位・倍率、状態値、レベル、ビットマップ、構造体、配列、日時など）に従って EDT を解釈。「未計測」などの特殊値、オーバーフロー/アンダーフロー、範囲外、係数プロパティの参照先も表示 |
| 値の解釈（MRA なし） | 動作状態、異常発生状態、エアコンの運転モード・温度、スマートメータの電力・電流など主要なプロパティのみ |
| 個別処理 | プロパティマップ(0x9B〜0x9F、リスト形式・ビットマップ形式とも)、インスタンスリスト(0xD5/0xD6)、クラスリスト(0xD7)、Version 情報(0x82)、設置場所(0x81) |
| Release 情報（MRA 読み込み時） | 各プロパティの定義がどの Release から有効か（例: `定義: Release D〜`）を表示。Release によって定義が異なるプロパティは、設定で選んだ Release の定義で解釈 |
| 表示言語 | 日本語（既定）/ 英語。クラス名・プロパティ名・値・ESV の説明が切り替わります |
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

## MRA の配置

1. エコーネットコンソーシアムの Web サイト（https://echonet.jp/ の規格書のページ）から
   「Machine Readable Appendix」をダウンロードし、利用条件を確認のうえ展開します。
2. 展開したフォルダ（`metaData.json`、`definitions`、`devices`、`superClass`、`nodeProfile` が入っているフォルダ。
   その親の `mraData` を含むフォルダでも可）を、次のどちらかに `echonet_mra` という名前で置きます。
   - 個人設定フォルダ: Windows は `%APPDATA%\Wireshark\echonet_mra`、macOS / Linux は `~/.config/wireshark/echonet_mra`
   - 個人 Lua プラグインフォルダ: `%APPDATA%\Wireshark\plugins\echonet_mra` など
   - 別の場所に置く場合は、設定の **MRA folder** にそのパスを指定します
3. Wireshark を再起動します。パケット詳細の先頭に `[MRA 1.3.1 (Release R), 56 classes: …]` と出ていれば読み込めています。
   見つからない場合は `[MRA not found (searched: …) - 内蔵の簡易表で表示しています]` と探した場所が表示されます。

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

- **Language / 表示言語**: 日本語（既定）または English
- **MRA folder**: MRA を置いたフォルダ（空欄なら上記の既定の場所を探します）
- **APPENDIX Release**: プロパティ定義を選ぶ基準の Release（既定「Latest (最新)」= MRA の最新）。
  機器が古い Release に準拠している場合に、その Release を選ぶと当時の定義で解釈します
- **UDP port**: 既定 3610
- **Heuristic detection on other UDP ports**: 3610 以外のポートでも EHD1=0x10 / EHD2=0x81・0x82 のパケットを自動検出（既定 OFF）

任意のポートを一時的に ECHONET Lite として解析したい場合は、パケットを右クリック →
**Decode As…** で「ECHONET Lite」を選んでも構いません。

## サンプルとテスト

- `samples/echonet_lite_sample.pcap`: 動作確認用のサンプル（25 フレーム）。
  ノード探索、インスタンスリスト通知、プロパティマップ（リスト／ビットマップ）、エアコンの状態取得、
  SetC、SetGet、Get_SNA、スマートメータ（積算電力量履歴の配列を含む）、ビットマップ型プロパティ、
  INFC/INFC_Res、形式2、壊れたフレームを含みます。
- `tools/make_sample_pcap.py`: 上記サンプルを生成する Python スクリプト（外部ライブラリ不要）。

```sh
python3 tools/make_sample_pcap.py samples/echonet_lite_sample.pcap
tshark -X lua_script:echonet_lite.lua -r samples/echonet_lite_sample.pcap -O echonetlite
# 英語表示・Release を指定する場合
tshark -X lua_script:echonet_lite.lua -o echonetlite.language:English -o "echonetlite.release:Release J" -r samples/echonet_lite_sample.pcap -O echonetlite
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

- 内蔵のクラス名: `BUILTIN_CLASS_NAMES` に `[0xGGCC] = { ja = "名称", en = "Name" }`
- 個別の値の解釈: `decode_special()` に条件を追加（MRA による汎用解釈より優先されます）
- MRA が新しくなった場合は、新しい MRA を `echonet_mra` フォルダに置き換えるだけで反映されます

収録していない EPC は「不明」と表示され、EDT は 16 進数で表示されます。

## 制限事項

- TCP 上の ECHONET Lite は未対応です（ヘッダに長さが無いため、1 セグメント 1 電文の前提でも誤判定しやすいため）。
- MRA（v1.3.1）に定義があるのは機器オブジェクト 55 クラスです。それ以外のクラスは
  内蔵のクラス名のみ表示し、プロパティはスーパークラス（0x80〜0x9F）の定義だけで解釈します。
  内蔵のクラス名・クラス固有プロパティ名の日本語表記は一部のみで、未収録のものは英語で表示します。
- 機器が準拠する Release を電文から自動判定することはしていません（設定で指定します）。
- 形式2（任意電文形式）はペイロードを 16 進表示するのみです。

## ライセンス

MIT

MRA はこのリポジトリに含まれていません。MRA の利用条件はエコーネットコンソーシアムの定めに従ってください。
