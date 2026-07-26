# tunnelserver — EZST向け複数ユーザーSSHトンネルサーバー

複数ユーザーが1台のVPS経由でMinecraftサーバー等のTCPサービスを公開できる、
独自SSHリバーストンネルサーバー(frp/ngrok的なものの自作版)。

## 特徴

- 公開鍵ごとにユーザーを識別(パスワード認証なし)
- 各ユーザーに**固定の公開ポート**を自動割当て・永続化(再接続しても同じポート)
- クライアントが要求したポート番号は無視し、必ずそのユーザーに割り当てられた
  ポートを使う(他人のポートを横取りできない設計)
- プロトコルはSSH標準の `tcpip-forward`(`ssh -R` と同じ)なので、
  クライアント側は標準SSHクライアント・Paramiko等どれでも接続可能
- session/direct-tcpip等、リバースフォワード以外のチャンネル要求はすべて拒否
  (シェルアクセスやSSH経由の踏み台利用を防止)

## 動作確認済み構成

- Go 1.22 + golang.org/x/crypto/ssh v0.24.0
- 実際にビルド・起動し、Paramikoクライアントから公開鍵認証 → ポート割当て →
  外部からのTCP接続 → ローカルサービスへの転送、まで一通り疎通確認済みです。

## VPS側セットアップ (Linux)

```bash
# Goのインストール(Ubuntu例)
sudo apt-get install -y golang-go

# ビルド
go mod tidy   # golang.org/x/crypto を取得(このVPSは通常インターネットに出られるはず)
go build -o tunnelserver .

# 設定ファイルを用意
cp config.example.json config.json
cp users.example.json users.json
# users.json に、各ユーザーのSSH公開鍵(ed25519推奨)を登録する
# port は 0 にしておけば初回接続時に自動割当てされ、以後固定される

# ファイアウォールで SSH待受ポート(例:2222)と
# port_pool_min〜port_pool_max の範囲を開放しておく

./tunnelserver -config config.json
```

### systemdサービス化の例

```ini
# /etc/systemd/system/tunnelserver.service
[Unit]
Description=EZST Tunnel Server
After=network.target

[Service]
WorkingDirectory=/opt/tunnelserver
ExecStart=/opt/tunnelserver/tunnelserver -config config.json
Restart=on-failure
User=tunnelsvc

[Install]
WantedBy=multi-user.target
```

## EZST(Windowsクライアント)側の実装イメージ

EZSTはPython/PyInstallerなので、**Paramiko**(pure Python実装、PyInstallerとの相性が良い)
を使えば、Windows側にsshクライアントの有無に依存せず組み込めます。
ユーザーがサーバー起動時に自動でトンネルを張るイメージです。

```python
import paramiko
import socket
import threading

def forward_handler(channel, origin, server, local_mc_port):
    """公開ポートへの着信を、ローカルのMinecraftサーバーへ橋渡しする"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", local_mc_port))

    def pipe(src, dst):
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)

    threading.Thread(target=pipe, args=(channel, sock), daemon=True).start()
    threading.Thread(target=pipe, args=(sock, channel), daemon=True).start()


def start_tunnel(vps_host, vps_port, username, private_key_path, local_mc_port):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # 本番ではホスト鍵検証を推奨
    client.connect(
        vps_host, port=vps_port, username=username,
        key_filename=private_key_path,
        look_for_keys=False, allow_agent=False,
    )
    transport = client.get_transport()

    # 0番を渡してもサーバー側が固定ポートを強制するので、
    # 戻り値の bound_port がユーザーの公開ポート番号になる
    handler = lambda ch, o, s: forward_handler(ch, o, s, local_mc_port)
    bound_port = transport.request_port_forward("", 0, handler=handler)

    print(f"公開URLは vps_host:{bound_port} です")
    return client  # 呼び出し側でこのclientを保持し、切断時にclient.close()する
```

EZST GUI上では「トンネルを開始」ボタン押下時に `start_tunnel()` を呼び、
ユーザーには `bound_port` を「あなたのサーバーアドレス」として表示する形が
シンプルです。

## セキュリティ上の注意点

- 現状は認証局(CA)なしの単純な公開鍵照合です。ユーザー数が増える場合は
  `users.json` の代わりにDBやEZServerToolAPI側で鍵を一元管理し、
  このサーバーはAPI経由で鍵一覧を取得する形に拡張するのがおすすめです。
- 1ユーザー1リスナー(多重公開禁止)にしていますが、将来的に複数サーバー
  同時公開に対応する場合はポート pool の割当てロジックを
  「ユーザー単位」から「(ユーザー, サーバー名)単位」に拡張してください。
- レート制限・帯域制限は未実装です。公開サービスにする場合は
  `iptables`/`tc` 等での制御を別途検討してください。
