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
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// ---------- 設定 ----------

// フリー枠(プロダクトキー未設定)の月間転送量上限
const bytesPerGB = 1024 * 1024 * 1024
const freeTierMonthlyLimitBytes int64 = 1 * bytesPerGB

type Config struct {
	SSHListen   string `json:"ssh_listen"`
	HTTPListen  string `json:"http_listen"` // 空文字なら登録APIを起動しない
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
	Username   string `json:"username"`
	PublicKey  string `json:"public_key"`            // "ssh-ed25519 AAAA... comment" 形式
	Port       int    `json:"port"`                  // 0なら次回接続時に自動割当てして保存する
	ProductKey string `json:"product_key,omitempty"` // 空ならフリー枠(月間1GB)扱い
	BytesUsed  int64  `json:"bytes_used"`            // UsageMonth中の累計転送バイト数(上り+下り合算)
	UsageMonth string `json:"usage_month,omitempty"` // "2006-01" 形式。月が変わったらリセットされる
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

// IsOverLimit はフリー枠ユーザーが当月の上限(1GB)を超えているか判定する。
// プロダクトキー保持ユーザーは常にfalse(無制限)。
func (us *UserStore) IsOverLimit(username string) bool {
	us.mu.Lock()
	defer us.mu.Unlock()
	for i := range us.entries {
		if us.entries[i].Username != username {
			continue
		}
		if us.entries[i].ProductKey != "" {
			return false
		}
		if us.entries[i].UsageMonth != currentUsageMonth() {
			return false // 新しい月にはまだ入っていないので0扱い
		}
		return us.entries[i].BytesUsed >= freeTierMonthlyLimitBytes
	}
	return false
}

// AddUsage は転送済みバイト数を加算する。月が変わっていればリセットしてから加算する。
func (us *UserStore) AddUsage(username string, n int64) {
	if n <= 0 {
		return
	}
	us.mu.Lock()
	defer us.mu.Unlock()
	for i := range us.entries {
		if us.entries[i].Username != username {
			continue
		}
		month := currentUsageMonth()
		if us.entries[i].UsageMonth != month {
			us.entries[i].UsageMonth = month
			us.entries[i].BytesUsed = 0
		}
		us.entries[i].BytesUsed += n
		if err := us.save(); err != nil {
			log.Printf("使用量保存エラー user=%s: %v", username, err)
		}
		return
	}
}

func currentUsageMonth() string {
	return time.Now().Format("2006-01")
}

// RegisterOrGet は公開鍵から自動登録する。
// 既に同じ公開鍵が登録済みならそのユーザー名を返す(冪等)。未登録なら自動生成したユーザー名で新規登録する。
// productKeyが空でなければ、そのユーザーをプロダクトキー保持(無制限枠)として記録/更新する。
func (us *UserStore) RegisterOrGet(pubKey ssh.PublicKey, productKey string) (username string, isNew bool, err error) {
	us.mu.Lock()
	defer us.mu.Unlock()

	keyStr := string(pubKey.Marshal())
	if idx, ok := us.byKeyStr[keyStr]; ok {
		if productKey != "" && us.entries[idx].ProductKey != productKey {
			us.entries[idx].ProductKey = productKey
			if err := us.save(); err != nil {
				return "", false, err
			}
		}
		return us.entries[idx].Username, false, nil
	}

	// 衝突しないユーザー名を生成(4バイトの乱数、"u-"接頭辞)
	var newName string
	for i := 0; i < 10; i++ {
		buf := make([]byte, 4)
		if _, err := rand.Read(buf); err != nil {
			return "", false, err
		}
		candidate := "u-" + hex.EncodeToString(buf)
		exists := false
		for _, e := range us.entries {
			if e.Username == candidate {
				exists = true
				break
			}
		}
		if !exists {
			newName = candidate
			break
		}
	}
	if newName == "" {
		return "", false, fmt.Errorf("ユーザー名の生成に失敗しました")
	}

	authKeyLine := string(ssh.MarshalAuthorizedKey(pubKey))
	us.entries = append(us.entries, UserEntry{
		Username:   newName,
		PublicKey:  authKeyLine[:len(authKeyLine)-1], // 末尾の改行を除去
		Port:       0,
		ProductKey: productKey,
	})
	us.byKeyStr[keyStr] = len(us.entries) - 1

	if err := us.save(); err != nil {
		// メモリ上のentriesは追加済みだが保存に失敗。呼び出し側にエラーを返す。
		return "", false, err
	}
	return newName, true, nil
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

// ---------- 登録API(HTTP) ----------

type rateLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	limit    int
	window   time.Duration
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{attempts: map[string][]time.Time{}, limit: limit, window: window}
}

func (r *rateLimiter) Allow(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-r.window)
	var kept []time.Time
	for _, t := range r.attempts[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= r.limit {
		r.attempts[key] = kept
		return false
	}
	r.attempts[key] = append(kept, now)
	return true
}

type registerRequest struct {
	PublicKey  string `json:"public_key"`
	ProductKey string `json:"product_key,omitempty"`
}

type registerResponse struct {
	Username string `json:"username"`
	SSHHost  string `json:"ssh_host,omitempty"`
	SSHPort  int    `json:"ssh_port,omitempty"`
	IsNew    bool   `json:"is_new"`
}

func startRegistrationServer(cfg *Config, users *UserStore) {
	limiter := newRateLimiter(5, time.Hour) // 同一IPから1時間に5回まで

	mux := http.NewServeMux()
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}

		clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		if !limiter.Allow(clientIP) {
			http.Error(w, "登録リクエストが多すぎます。しばらく待ってから再試行してください", http.StatusTooManyRequests)
			return
		}

		var req registerRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&req); err != nil {
			http.Error(w, "リクエストの形式が不正です", http.StatusBadRequest)
			return
		}

		pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PublicKey))
		if err != nil {
			http.Error(w, "公開鍵の形式が不正です(ssh-ed25519形式を送ってください)", http.StatusBadRequest)
			return
		}
		if pubKey.Type() != ssh.KeyAlgoED25519 {
			http.Error(w, "ed25519形式の公開鍵のみ受け付けています", http.StatusBadRequest)
			return
		}

		username, isNew, err := users.RegisterOrGet(pubKey, req.ProductKey)
		if err != nil {
			log.Printf("登録エラー: %v", err)
			http.Error(w, "登録処理に失敗しました", http.StatusInternalServerError)
			return
		}

		log.Printf("登録API: user=%s isNew=%v remote=%s", username, isNew, clientIP)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(registerResponse{
			Username: username,
			IsNew:    isNew,
		})
	})

	log.Printf("登録API起動: %s", cfg.HTTPListen)
	if err := http.ListenAndServe(cfg.HTTPListen, mux); err != nil {
		log.Fatalf("登録APIの起動に失敗: %v", err)
	}
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
	username    string
	sconn       *ssh.ServerConn
	listener    net.Listener // このユーザーが公開しているポートのlistener(1接続につき1つまで)
	forwardAddr string       // クライアントがtcpip-forwardで要求した元のアドレス文字列(空文字含む)
	users       *UserStore   // 使用量記録用
	mu          sync.Mutex
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

	if cfg.HTTPListen != "" {
		go startRegistrationServer(cfg, users)
	}

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

	state := &connState{username: username, sconn: sconn, users: users}

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

	if users.IsOverLimit(state.username) {
		log.Printf("user=%s は無料枠の月間上限(1GB)に達しているためトンネルを拒否します", state.username)
		if req.WantReply {
			req.Reply(false, nil)
		}
		return
	}

	state.mu.Lock()
	state.forwardAddr = msg.Addr
	state.mu.Unlock()

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

	state.mu.Lock()
	addr := state.forwardAddr
	state.mu.Unlock()

	payload := forwardedTCPPayload{
		Addr:       addr,
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

	// 双方向コピー。片方向がEOFに達しても、相手方向がまだデータを
	// 送信中の可能性があるため、即座に両方を完全クローズしない。
	// 半クローズ(CloseWrite)で「これ以上送らない」ことだけを伝え、
	// 両方向が終わってから最後にまとめて閉じる。
	// (これをやらないと、未送信/未読データが残ったソケットをCloseした際に
	//  OSがRST(強制リセット)を送ってしまい、Minecraftクライアント側で
	//  "Connection reset" として表示される)
	log.Printf("チャンネル開設成功: user=%s remote=%s", state.username, publicConn.RemoteAddr())

	var wg sync.WaitGroup
	var n1, n2 int64
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, err := io.Copy(ch, publicConn)
		n1 = n
		log.Printf("client->local: %d bytes, err=%v (user=%s)", n, err, state.username)
		ch.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		n, err := io.Copy(publicConn, ch)
		n2 = n
		log.Printf("local->client: %d bytes, err=%v (user=%s)", n, err, state.username)
		if tcpConn, ok := publicConn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()
	wg.Wait()
	if state.users != nil {
		state.users.AddUsage(state.username, n1+n2)
	}
	log.Printf("ブリッジ終了: user=%s", state.username)
}
