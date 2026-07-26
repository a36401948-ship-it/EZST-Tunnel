// tunnelserver - 複数ユーザー向けSSHリバーストンネルサーバー
//
// クライアントは標準の "ssh -R <割当ポート>:localhost:<ローカルポート> user@host -p 2222"
// と同じプロトコル(RFC4254 tcpip-forward)で接続する。特別なクライアント実装は不要で、
// EZServerTool側はParamiko等の一般的なSSHクライアントライブラリで接続できる。
//
// 各ユーザーは公開鍵で識別され、公開する外部ポートは users.json 内で固定/自動割当てされる。
// クライアントが要求したポート番号に関わらず、サーバーは必ずそのユーザーに割り当てられた
// ポートを使う(他ユーザーのポートを横取りできないようにするため)。
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"

	"golang.org/x/crypto/ssh"
)

// ---------- 設定 ----------

type Config struct {
	SSHListen   string `json:"ssh_listen"`
	HostKeyPath string `json:"host_key_path"`
	UsersFile   string `json:"users_file"`
	PortPoolMin int    `json:"port_pool_min"`
	PortPoolMax int    `json:"port_pool_max"`
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	if c.SSHListen == "" {
		c.SSHListen = ":2222"
	}
	if c.HostKeyPath == "" {
		c.HostKeyPath = "host_key.pem"
	}
	if c.UsersFile == "" {
		c.UsersFile = "users.json"
	}
	return &c, nil
}

// ---------- ユーザー管理 ----------

type UserEntry struct {
	Username  string `json:"username"`
	PublicKey string `json:"public_key"` // "ssh-ed25519 AAAA... comment" 形式
	Port      int    `json:"port"`       // 0なら次回接続時に自動割当てして保存する
}

type UsersFile struct {
	Users []UserEntry `json:"users"`
}

type UserStore struct {
	mu       sync.Mutex
	path     string
	entries  []UserEntry
	byKeyStr map[string]int // marshaled pubkey(string化) -> entries index
	poolMin  int
	poolMax  int
}

func loadUserStore(path string, poolMin, poolMax int) (*UserStore, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var uf UsersFile
	if err := json.Unmarshal(data, &uf); err != nil {
		return nil, err
	}
	us := &UserStore{
		path:     path,
		entries:  uf.Users,
		byKeyStr: map[string]int{},
		poolMin:  poolMin,
		poolMax:  poolMax,
	}
	for i, e := range uf.Users {
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(e.PublicKey))
		if err != nil {
			log.Printf("警告: ユーザー %s の公開鍵をパースできません: %v", e.Username, err)
			continue
		}
		us.byKeyStr[string(pk.Marshal())] = i
	}
	return us, nil
}

func (us *UserStore) save() error {
	uf := UsersFile{Users: us.entries}
	data, err := json.MarshalIndent(uf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(us.path, data, 0600)
}

// Authenticate はオファーされた公開鍵からユーザー名を返す。見つからなければ空文字。
func (us *UserStore) Authenticate(key ssh.PublicKey) (string, bool) {
	us.mu.Lock()
	defer us.mu.Unlock()
	idx, ok := us.byKeyStr[string(key.Marshal())]
	if !ok {
		return "", false
	}
	return us.entries[idx].Username, true
}

// AssignedPort はユーザーの固定ポートを返す。未割当てなら空きポートを自動割当てして保存する。
func (us *UserStore) AssignedPort(username string) (int, error) {
	us.mu.Lock()
	defer us.mu.Unlock()
	used := map[int]bool{}
	idx := -1
	for i, e := range us.entries {
		if e.Port != 0 {
			used[e.Port] = true
		}
		if e.Username == username {
			idx = i
		}
	}
	if idx == -1 {
		return 0, fmt.Errorf("ユーザーが見つかりません: %s", username)
	}
	if us.entries[idx].Port != 0 {
		return us.entries[idx].Port, nil
	}
	for p := us.poolMin; p <= us.poolMax; p++ {
		if !used[p] {
			us.entries[idx].Port = p
			if err := us.save(); err != nil {
				return 0, err
			}
			return p, nil
		}
	}
	return 0, fmt.Errorf("空きポートがありません(pool %d-%d)", us.poolMin, us.poolMax)
}

// ---------- ホスト鍵 ----------

func loadOrCreateHostKey(path string) (ssh.Signer, error) {
	if data, err := os.ReadFile(path); err == nil {
		return ssh.ParsePrivateKey(data)
	}
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, err
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
	pemBytes := pem.EncodeToMemory(block)
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		return nil, err
	}
	log.Printf("新しいホスト鍵を生成しました: %s", path)
	return ssh.ParsePrivateKey(pemBytes)
}

// ---------- RFC4254 メッセージ ----------

type tcpipForwardMsg struct {
	Addr string
	Port uint32
}

type tcpipForwardReplyMsg struct {
	Port uint32
}

type forwardedTCPPayload struct {
	Addr       string
	Port       uint32
	OriginAddr string
	OriginPort uint32
}

// ---------- 接続ごとの状態 ----------

type connState struct {
	username string
	sconn    *ssh.ServerConn
	listener net.Listener // このユーザーが公開しているポートのlistener(1接続につき1つまで)
	mu       sync.Mutex
}

func main() {
	cfgPath := flag.String("config", "config.json", "設定ファイルのパス")
	flag.Parse()

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("設定ファイルを読み込めません: %v", err)
	}
	users, err := loadUserStore(cfg.UsersFile, cfg.PortPoolMin, cfg.PortPoolMax)
	if err != nil {
		log.Fatalf("ユーザーファイルを読み込めません: %v", err)
	}
	hostKey, err := loadOrCreateHostKey(cfg.HostKeyPath)
	if err != nil {
		log.Fatalf("ホスト鍵の準備に失敗: %v", err)
	}

	sshConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			username, ok := users.Authenticate(key)
			if !ok {
				return nil, fmt.Errorf("認証失敗: 未登録の公開鍵です")
			}
			return &ssh.Permissions{
				Extensions: map[string]string{"username": username},
			}, nil
		},
	}
	sshConfig.AddHostKey(hostKey)

	listener, err := net.Listen("tcp", cfg.SSHListen)
	if err != nil {
		log.Fatalf("リッスンに失敗 (%s): %v", cfg.SSHListen, err)
	}
	log.Printf("SSHトンネルサーバー起動: %s", cfg.SSHListen)

	for {
		nConn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConn(nConn, sshConfig, users)
	}
}

func handleConn(nConn net.Conn, sshConfig *ssh.ServerConfig, users *UserStore) {
	sconn, chans, reqs, err := ssh.NewServerConn(nConn, sshConfig)
	if err != nil {
		log.Printf("ハンドシェイク失敗 (%s): %v", nConn.RemoteAddr(), err)
		return
	}
	username := sconn.Permissions.Extensions["username"]
	log.Printf("接続: user=%s remote=%s", username, sconn.RemoteAddr())

	state := &connState{username: username, sconn: sconn}

	// クライアントからのチャンネル開設要求はすべて拒否する
	// (このサーバーはリバースフォワード専用。session/direct-tcpip等は許可しない)
	go func() {
		for newCh := range chans {
			newCh.Reject(ssh.Prohibited, "このサーバーはリバースポートフォワード専用です")
		}
	}()

	go func() {
		defer func() {
			state.mu.Lock()
			if state.listener != nil {
				state.listener.Close()
			}
			state.mu.Unlock()
			sconn.Close()
			log.Printf("切断: user=%s", username)
		}()
		for req := range reqs {
			switch req.Type {
			case "tcpip-forward":
				handleTCPIPForward(state, req, users)
			case "cancel-tcpip-forward":
				state.mu.Lock()
				if state.listener != nil {
					state.listener.Close()
					state.listener = nil
				}
				state.mu.Unlock()
				if req.WantReply {
					req.Reply(true, nil)
				}
			default:
				if req.WantReply {
					req.Reply(false, nil)
				}
			}
		}
	}()

	sconn.Wait()
}

func handleTCPIPForward(state *connState, req *ssh.Request, users *UserStore) {
	var msg tcpipForwardMsg
	if err := ssh.Unmarshal(req.Payload, &msg); err != nil {
		if req.WantReply {
			req.Reply(false, nil)
		}
		return
	}

	assignedPort, err := users.AssignedPort(state.username)
	if err != nil {
		log.Printf("ポート割当て失敗 user=%s: %v", state.username, err)
		if req.WantReply {
			req.Reply(false, nil)
		}
		return
	}

	state.mu.Lock()
	if state.listener != nil {
		// 既に公開中。1ユーザー1リスナーのみ許可(多重公開は禁止)
		state.mu.Unlock()
		log.Printf("user=%s は既にポート%dを公開中です", state.username, assignedPort)
		if req.WantReply {
			req.Reply(false, nil)
		}
		return
	}
	state.mu.Unlock()

	// クライアントが何を要求してきても、必ず「そのユーザーに割り当てられたポート」を使う
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", assignedPort))
	if err != nil {
		log.Printf("listen失敗 user=%s port=%d: %v", state.username, assignedPort, err)
		if req.WantReply {
			req.Reply(false, nil)
		}
		return
	}

	state.mu.Lock()
	state.listener = ln
	state.mu.Unlock()

	log.Printf("公開開始: user=%s 公開ポート=%d", state.username, assignedPort)

	if req.WantReply {
		reply := tcpipForwardReplyMsg{Port: uint32(assignedPort)}
		req.Reply(true, ssh.Marshal(&reply))
	}

	go acceptLoop(state, ln, assignedPort)
}

func acceptLoop(state *connState, ln net.Listener, publicPort int) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listenerがCloseされたら終了
		}
		go bridgeConnection(state, conn, publicPort)
	}
}

func bridgeConnection(state *connState, publicConn net.Conn, publicPort int) {
	defer publicConn.Close()

	origHost, origPortStr, _ := net.SplitHostPort(publicConn.RemoteAddr().String())
	var origPort uint32
	fmt.Sscanf(origPortStr, "%d", &origPort)

	payload := forwardedTCPPayload{
		Addr:       "0.0.0.0",
		Port:       uint32(publicPort),
		OriginAddr: origHost,
		OriginPort: origPort,
	}

	ch, reqs, err := state.sconn.OpenChannel("forwarded-tcpip", ssh.Marshal(&payload))
	if err != nil {
		log.Printf("チャンネル開設失敗 user=%s: %v", state.username, err)
		return
	}
	defer ch.Close()
	go ssh.DiscardRequests(reqs)

	done := make(chan struct{}, 2)
	go func() {
		io.Copy(ch, publicConn)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(publicConn, ch)
		done <- struct{}{}
	}()
	<-done
}
