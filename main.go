package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/websocket"
	"golang.org/x/oauth2"
)

//go:embed web/*
var webAssets embed.FS

type serverEvent struct {
	Type          string `json:"type"`
	Level         string `json:"level,omitempty"`
	Message       string `json:"message,omitempty"`
	ChannelID     uint32 `json:"channelId,omitempty"`
	SenderID      uint32 `json:"senderId,omitempty"`
	TalkerID      uint32 `json:"talkerId,omitempty"`
	TalkAllowed   bool   `json:"talkAllowed,omitempty"`
	RelayHost     string `json:"relayHost,omitempty"`
	RelayPort     int    `json:"relayPort,omitempty"`
	CryptoMode    string `json:"cryptoMode,omitempty"`
	CodecMode     int    `json:"codecMode,omitempty"`
	PCMOnly       bool   `json:"pcmOnly,omitempty"`
	UplinkCodec   string `json:"uplinkCodec,omitempty"`
	DownlinkCodec string `json:"downlinkCodec,omitempty"`
}

type clientCommand struct {
	Type          string `json:"type"`
	RelayHost     string `json:"relayHost,omitempty"`
	RelayPort     int    `json:"relayPort,omitempty"`
	RelayAddress  string `json:"relayAddress,omitempty"`
	ChannelID     uint32 `json:"channelId,omitempty"`
	SenderID      uint32 `json:"senderId,omitempty"`
	Password      string `json:"password,omitempty"`
	CryptoMode    string `json:"cryptoMode,omitempty"`
	CodecMode     int    `json:"codecMode,omitempty"`
	Codec2Lib     string `json:"codec2Lib,omitempty"`
	OpusLib       string `json:"opusLib,omitempty"`
	UplinkCodec   string `json:"uplinkCodec,omitempty"`
	DownlinkCodec string `json:"downlinkCodec,omitempty"`
	PCMOnly       *bool  `json:"pcmOnly,omitempty"`
	Pressed       *bool  `json:"pressed,omitempty"`
}

type wsMessage struct {
	msgType int
	payload []byte
}

type authMode string

const (
	authModeNone  authMode = "none"
	authModeBasic authMode = "basic"
	authModeOIDC  authMode = "oidc"
)

const (
	oidcSessionCookieName = "incomudon_oidc_session"
	oidcStateCookieName   = "incomudon_oidc_state"
)

type oidcRuntime struct {
	issuer        string
	oauth2Config  oauth2.Config
	verifier      *oidc.IDTokenVerifier
	sessionSecret []byte
}

type oidcStateCookie struct {
	State string `json:"state"`
	Nonce string `json:"nonce"`
	Next  string `json:"next"`
	Exp   int64  `json:"exp"`
}

type oidcSessionCookie struct {
	Sub   string `json:"sub"`
	Email string `json:"email,omitempty"`
	Name  string `json:"name,omitempty"`
	Exp   int64  `json:"exp"`
}

type appServer struct {
	basePath          string
	static            http.Handler
	indexT            *template.Template
	codec2LibDefault  string
	opusLibDefault    string
	fixedRelayEnabled bool
	fixedRelayHost    string
	fixedRelayPort    int
	wsToken           string
	authMode          authMode
	basicUser         string
	basicPass         string
	oidc              *oidcRuntime

	upgrader websocket.Upgrader
}

func main() {
	listenAddr := flag.String("listen", ":8080", "HTTP listen address")
	basePathFlag := flag.String("base-path", "/", "base path for reverse proxy deployment (e.g. /pwa)")
	codec2LibFlag := flag.String("codec2-lib", os.Getenv("INCOMUDON_CODEC2_LIB"), "optional path to user-provided libcodec2.so")
	opusLibFlag := flag.String("opus-lib", os.Getenv("INCOMUDON_OPUS_LIB"), "optional path to user-provided libopus.so")
	fixedRelayFlag := flag.String("fixed-relay", os.Getenv("INCOMUDON_FIXED_RELAY"), "optional fixed relay host[:port]; when set, browser relay host/port is ignored")
	wsTokenFlag := flag.String("ws-token", os.Getenv("INCOMUDON_WS_TOKEN"), "optional shared token required for websocket connections")
	authModeFlag := flag.String("auth-mode", getenvOrDefault("INCOMUDON_AUTH_MODE", string(authModeNone)), "auth mode: none|basic|oidc")
	basicUserFlag := flag.String("basic-user", os.Getenv("INCOMUDON_BASIC_USER"), "basic auth username (auth-mode=basic)")
	basicPassFlag := flag.String("basic-pass", os.Getenv("INCOMUDON_BASIC_PASS"), "basic auth password (auth-mode=basic)")
	oidcIssuerFlag := flag.String("oidc-issuer", os.Getenv("INCOMUDON_OIDC_ISSUER"), "OIDC issuer URL (auth-mode=oidc)")
	oidcClientIDFlag := flag.String("oidc-client-id", os.Getenv("INCOMUDON_OIDC_CLIENT_ID"), "OIDC client ID (auth-mode=oidc)")
	oidcClientSecretFlag := flag.String("oidc-client-secret", os.Getenv("INCOMUDON_OIDC_CLIENT_SECRET"), "OIDC client secret (auth-mode=oidc, optional for public clients)")
	oidcRedirectURLFlag := flag.String("oidc-redirect-url", os.Getenv("INCOMUDON_OIDC_REDIRECT_URL"), "OIDC redirect URL override (auth-mode=oidc)")
	oidcScopesFlag := flag.String("oidc-scopes", getenvOrDefault("INCOMUDON_OIDC_SCOPES", "openid,profile,email"), "OIDC scopes CSV (auth-mode=oidc)")
	oidcSessionSecretFlag := flag.String("oidc-session-secret", os.Getenv("INCOMUDON_OIDC_SESSION_SECRET"), "OIDC session signing secret (auth-mode=oidc)")
	flag.Parse()

	basePath := normalizeBasePath(*basePathFlag)
	fixedRelayHost, fixedRelayPort, fixedRelayEnabled, err := parseFixedRelayConfig(*fixedRelayFlag)
	if err != nil {
		log.Fatalf("invalid fixed relay setting: %v", err)
	}
	mode, err := parseAuthMode(*authModeFlag)
	if err != nil {
		log.Fatalf("invalid auth mode: %v", err)
	}
	basicUser := strings.TrimSpace(*basicUserFlag)
	basicPass := strings.TrimSpace(*basicPassFlag)
	if mode == authModeBasic {
		if basicUser == "" || basicPass == "" {
			log.Fatalf("auth-mode=basic requires -basic-user and -basic-pass")
		}
	}

	var oidcRT *oidcRuntime
	if mode == authModeOIDC {
		oidcRT, err = newOIDCRuntime(oidcRuntimeConfig{
			Issuer:        strings.TrimSpace(*oidcIssuerFlag),
			ClientID:      strings.TrimSpace(*oidcClientIDFlag),
			ClientSecret:  strings.TrimSpace(*oidcClientSecretFlag),
			RedirectURL:   strings.TrimSpace(*oidcRedirectURLFlag),
			Scopes:        parseCSV(*oidcScopesFlag),
			SessionSecret: strings.TrimSpace(*oidcSessionSecretFlag),
		})
		if err != nil {
			log.Fatalf("failed to initialize OIDC: %v", err)
		}
	}

	subFS, err := fs.Sub(webAssets, "web")
	if err != nil {
		log.Fatalf("failed to load embedded web assets: %v", err)
	}

	indexRaw, err := fs.ReadFile(subFS, "index.html")
	if err != nil {
		log.Fatalf("failed to read index.html: %v", err)
	}
	indexTemplate, err := template.New("index").Parse(string(indexRaw))
	if err != nil {
		log.Fatalf("failed to parse index template: %v", err)
	}

	app := &appServer{
		basePath:          basePath,
		static:            http.FileServer(http.FS(subFS)),
		indexT:            indexTemplate,
		codec2LibDefault:  strings.TrimSpace(*codec2LibFlag),
		opusLibDefault:    strings.TrimSpace(*opusLibFlag),
		fixedRelayEnabled: fixedRelayEnabled,
		fixedRelayHost:    fixedRelayHost,
		fixedRelayPort:    fixedRelayPort,
		wsToken:           strings.TrimSpace(*wsTokenFlag),
		authMode:          mode,
		basicUser:         basicUser,
		basicPass:         basicPass,
		oidc:              oidcRT,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  4096,
			WriteBufferSize: 4096,
			CheckOrigin: func(r *http.Request) bool {
				// Keep this permissive so reverse proxy and custom host routing keep working.
				return true
			},
		},
	}

	mux := http.NewServeMux()
	app.registerRoutes(mux)

	server := &http.Server{
		Addr:              *listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	prefix := "/"
	if basePath != "" {
		prefix = basePath + "/"
	}
	log.Printf("IncomUdon relay PWA client listening on http://0.0.0.0%s%s", *listenAddr, prefix)
	if app.fixedRelayEnabled {
		log.Printf("Fixed relay target is enabled: %s", net.JoinHostPort(app.fixedRelayHost, strconv.Itoa(app.fixedRelayPort)))
	}
	if app.wsToken != "" {
		log.Printf("WebSocket token authentication is enabled")
	}
	if app.authMode == authModeBasic {
		log.Printf("HTTP Basic authentication is enabled")
	}
	if app.authMode == authModeOIDC {
		log.Printf("OIDC authentication is enabled (issuer=%s)", app.oidc.issuer)
	}
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("http server error: %v", err)
	}
}

func normalizeBasePath(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || trimmed == "/" {
		return ""
	}
	if !strings.HasPrefix(trimmed, "/") {
		trimmed = "/" + trimmed
	}
	return strings.TrimRight(trimmed, "/")
}

func (a *appServer) registerRoutes(mux *http.ServeMux) {
	if a.basePath == "" {
		mux.HandleFunc("/auth/check", a.handleAuthCheck)
		mux.HandleFunc("/auth/logout", a.handleAuthLogout)
		if a.authMode == authModeOIDC {
			mux.HandleFunc("/auth/login", a.handleOIDCLogin)
			mux.HandleFunc("/auth/callback", a.handleOIDCCallback)
		}
	} else {
		mux.HandleFunc(a.basePath+"/auth/check", a.handleAuthCheck)
		mux.HandleFunc(a.basePath+"/auth/logout", a.handleAuthLogout)
		if a.authMode == authModeOIDC {
			mux.HandleFunc(a.basePath+"/auth/login", a.handleOIDCLogin)
			mux.HandleFunc(a.basePath+"/auth/callback", a.handleOIDCCallback)
		}
	}

	if a.basePath == "" {
		mux.HandleFunc("/ws", a.handleWS)
		mux.HandleFunc("/", a.handleStatic)
		return
	}

	mux.HandleFunc(a.basePath, func(w http.ResponseWriter, r *http.Request) {
		redirectWithQuery(w, r, a.basePath+"/")
	})
	mux.HandleFunc(a.basePath+"/ws", a.handleWS)
	mux.HandleFunc(a.basePath+"/", a.handleStatic)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		redirectWithQuery(w, r, a.basePath+"/")
	})
}

func (a *appServer) handleStatic(w http.ResponseWriter, r *http.Request) {
	if !a.authorizeRequest(w, r, false) {
		return
	}

	relPath := r.URL.Path
	if a.basePath != "" {
		relPath = strings.TrimPrefix(relPath, a.basePath)
	}
	if relPath == "" {
		relPath = "/"
	}

	if relPath == "/" || relPath == "/index.html" {
		a.serveIndex(w, r)
		return
	}

	if relPath == "/sw.js" {
		w.Header().Set("Cache-Control", "no-cache")
	}

	r2 := r.Clone(r.Context())
	r2.URL.Path = relPath
	a.static.ServeHTTP(w, r2)
}

func (a *appServer) serveIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")

	data := struct {
		BasePath          string
		FixedRelayEnabled bool
		FixedRelayHost    string
		FixedRelayPort    int
		WSTokenRequired   bool
		AuthMode          string
	}{
		BasePath:          a.basePath,
		FixedRelayEnabled: a.fixedRelayEnabled,
		FixedRelayHost:    a.fixedRelayHost,
		FixedRelayPort:    a.fixedRelayPort,
		WSTokenRequired:   strings.TrimSpace(a.wsToken) != "",
		AuthMode:          string(a.authMode),
	}
	if err := a.indexT.Execute(w, data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

func (a *appServer) handleWS(w http.ResponseWriter, r *http.Request) {
	if !a.authorizeRequest(w, r, true) {
		return
	}

	if a.wsToken != "" && !authenticateWebSocketRequest(r, a.wsToken) {
		log.Printf("websocket unauthorized: remote=%s path=%s", r.RemoteAddr, r.URL.Path)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	conn, err := a.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
	conn.SetPongHandler(func(string) error {
		_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		return nil
	})

	writeCh := make(chan wsMessage, 256)
	writerDone := make(chan struct{})
	go wsWriter(conn, writeCh, writerDone)

	closeWriter := sync.Once{}
	shutdownWriter := func() {
		closeWriter.Do(func() {
			close(writeCh)
			<-writerDone
		})
	}
	defer shutdownWriter()

	enqueueJSON := func(event serverEvent) {
		payload, err := json.Marshal(event)
		if err != nil {
			return
		}
		select {
		case writeCh <- wsMessage{msgType: websocket.TextMessage, payload: payload}:
		default:
			// Keep the UI responsive even if browser is temporarily slow.
		}
	}

	enqueuePCM := func(frame []byte) {
		payload := make([]byte, 1+len(frame))
		payload[0] = serverBinaryAudio
		copy(payload[1:], frame)
		select {
		case writeCh <- wsMessage{msgType: websocket.BinaryMessage, payload: payload}:
		default:
			// Drop audio frames under backpressure.
		}
	}
	enqueueOpus := func(packet []byte) {
		payload := make([]byte, 1+len(packet))
		payload[0] = serverBinaryOpus
		copy(payload[1:], packet)
		select {
		case writeCh <- wsMessage{msgType: websocket.BinaryMessage, payload: payload}:
		default:
			// Drop audio frames under backpressure.
		}
	}

	enqueueJSON(serverEvent{Type: "ready", Message: "websocket connected"})

	var session *relaySession
	defer func() {
		if session != nil {
			session.Close()
		}
	}()

	for {
		messageType, payload, err := conn.ReadMessage()
		if err != nil {
			return
		}

		switch messageType {
		case websocket.TextMessage:
			var cmd clientCommand
			if err := json.Unmarshal(payload, &cmd); err != nil {
				enqueueJSON(serverEvent{Type: "status", Level: "error", Message: "invalid JSON command"})
				continue
			}
			handledSession, closeCurrent := handleClientCommand(
				cmd,
				session,
				enqueueJSON,
				enqueuePCM,
				enqueueOpus,
				a.codec2LibDefault,
				a.opusLibDefault,
				a.fixedRelayEnabled,
				a.fixedRelayHost,
				a.fixedRelayPort,
			)
			if closeCurrent && session != nil {
				session.Close()
			}
			session = handledSession
		case websocket.BinaryMessage:
			if session == nil {
				enqueueJSON(serverEvent{Type: "status", Level: "warn", Message: "audio ignored: not connected"})
				continue
			}
			handleBinaryFromBrowser(payload, session)
		}
	}
}

func wsWriter(conn *websocket.Conn, writeCh <-chan wsMessage, done chan<- struct{}) {
	defer close(done)

	pingTicker := time.NewTicker(25 * time.Second)
	defer pingTicker.Stop()

	for {
		select {
		case msg, ok := <-writeCh:
			if !ok {
				_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
				_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
				return
			}
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err := conn.WriteMessage(msg.msgType, msg.payload); err != nil {
				return
			}
		case <-pingTicker.C:
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func handleBinaryFromBrowser(payload []byte, session *relaySession) {
	if len(payload) == 0 {
		return
	}
	session.HandleBrowserBinary(payload)
}

func handleClientCommand(
	cmd clientCommand,
	current *relaySession,
	enqueueJSON func(serverEvent),
	enqueuePCM func([]byte),
	enqueueOpus func([]byte),
	defaultCodec2Lib string,
	defaultOpusLib string,
	fixedRelayEnabled bool,
	fixedRelayHost string,
	fixedRelayPort int,
) (*relaySession, bool) {
	switch cmd.Type {
	case "connect":
		cfg, err := buildSessionConfig(cmd, defaultCodec2Lib, defaultOpusLib, fixedRelayEnabled, fixedRelayHost, fixedRelayPort)
		if err != nil {
			enqueueJSON(serverEvent{Type: "status", Level: "error", Message: err.Error()})
			return current, false
		}

		newSession, err := newRelaySession(cfg, sessionCallbacks{
			onEvent: enqueueJSON,
			onPCM:   enqueuePCM,
			onOpus:  enqueueOpus,
		})
		if err != nil {
			enqueueJSON(serverEvent{Type: "status", Level: "error", Message: err.Error()})
			return current, false
		}
		newSession.Start()
		effective := newSession.EffectiveConfig()

		enqueueJSON(serverEvent{
			Type:          "connected",
			Message:       "relay session started",
			RelayHost:     effective.RelayHost,
			RelayPort:     effective.RelayPort,
			ChannelID:     effective.ChannelID,
			SenderID:      effective.SenderID,
			CryptoMode:    string(effective.CryptoMode),
			CodecMode:     effective.CodecMode,
			PCMOnly:       effective.PCMOnly,
			UplinkCodec:   effective.UplinkCodec,
			DownlinkCodec: effective.DownlinkCodec,
		})
		return newSession, true

	case "disconnect":
		enqueueJSON(serverEvent{Type: "disconnected", Message: "relay session stopped"})
		return nil, true

	case "ptt":
		if current == nil {
			enqueueJSON(serverEvent{Type: "status", Level: "warn", Message: "PTT ignored: not connected"})
			return current, false
		}
		if cmd.Pressed != nil {
			current.SetPTT(*cmd.Pressed)
		}
		return current, false

	case "set_codec":
		if current == nil {
			enqueueJSON(serverEvent{Type: "status", Level: "warn", Message: "set_codec ignored: not connected"})
			return current, false
		}
		pcmOnly := true
		if cmd.PCMOnly != nil {
			pcmOnly = *cmd.PCMOnly
		}
		mode := cmd.CodecMode
		if mode == 0 {
			mode = 2400
		}
		current.UpdateCodec(mode, pcmOnly)
		enqueueJSON(serverEvent{Type: "status", Level: "info", Message: "codec config updated"})
		return current, false

	default:
		enqueueJSON(serverEvent{Type: "status", Level: "warn", Message: fmt.Sprintf("unknown command: %s", cmd.Type)})
		return current, false
	}
}

func buildSessionConfig(
	cmd clientCommand,
	defaultCodec2Lib string,
	defaultOpusLib string,
	fixedRelayEnabled bool,
	fixedRelayHost string,
	fixedRelayPort int,
) (sessionConfig, error) {
	host, port, err := parseRelayTarget(cmd)
	if err != nil {
		return sessionConfig{}, err
	}
	if fixedRelayEnabled {
		host = fixedRelayHost
		port = fixedRelayPort
	}

	if cmd.ChannelID == 0 {
		return sessionConfig{}, fmt.Errorf("channelId must be greater than 0")
	}

	mode := cryptoAESGCM
	if strings.TrimSpace(cmd.CryptoMode) != "" {
		parsed, ok := parseCryptoMode(strings.TrimSpace(cmd.CryptoMode))
		if !ok {
			return sessionConfig{}, fmt.Errorf("unsupported cryptoMode: %s", cmd.CryptoMode)
		}
		mode = parsed
	}

	senderID := cmd.SenderID
	if senderID == 0 {
		senderID = randomSenderID()
	}

	codecMode := cmd.CodecMode
	if codecMode == 0 {
		codecMode = 2400
	}
	codecMode = normalizeCodecMode(codecMode)

	pcmOnly := true
	if cmd.PCMOnly != nil {
		pcmOnly = *cmd.PCMOnly
	}

	codec2LibPath := strings.TrimSpace(cmd.Codec2Lib)
	if codec2LibPath == "" {
		codec2LibPath = strings.TrimSpace(defaultCodec2Lib)
	}
	opusLibPath := strings.TrimSpace(cmd.OpusLib)
	if opusLibPath == "" {
		opusLibPath = strings.TrimSpace(defaultOpusLib)
	}

	cfg := sessionConfig{
		RelayHost:     host,
		RelayPort:     port,
		ChannelID:     cmd.ChannelID,
		SenderID:      senderID,
		Password:      cmd.Password,
		CryptoMode:    mode,
		CodecMode:     codecMode,
		PCMOnly:       pcmOnly,
		Codec2LibPath: codec2LibPath,
		OpusLibPath:   opusLibPath,
		UplinkCodec:   cmd.UplinkCodec,
		DownlinkCodec: cmd.DownlinkCodec,
	}
	return cfg, nil
}

type oidcRuntimeConfig struct {
	Issuer        string
	ClientID      string
	ClientSecret  string
	RedirectURL   string
	Scopes        []string
	SessionSecret string
}

func parseAuthMode(value string) (authMode, error) {
	mode := authMode(strings.ToLower(strings.TrimSpace(value)))
	switch mode {
	case authModeNone, authModeBasic, authModeOIDC:
		return mode, nil
	default:
		return authModeNone, fmt.Errorf("unsupported auth mode: %s", value)
	}
}

func getenvOrDefault(key string, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func parseCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, item := range parts {
		token := strings.TrimSpace(item)
		if token == "" {
			continue
		}
		if _, ok := seen[token]; ok {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, token)
	}
	return out
}

func ensureOpenIDScope(scopes []string) []string {
	out := make([]string, 0, len(scopes)+1)
	hasOpenID := false
	for _, scope := range scopes {
		token := strings.TrimSpace(scope)
		if token == "" {
			continue
		}
		if token == "openid" {
			hasOpenID = true
		}
		out = append(out, token)
	}
	if !hasOpenID {
		out = append([]string{"openid"}, out...)
	}
	return out
}

func newOIDCRuntime(cfg oidcRuntimeConfig) (*oidcRuntime, error) {
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("oidc issuer is required")
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("oidc client id is required")
	}
	if cfg.SessionSecret == "" {
		return nil, fmt.Errorf("oidc session secret is required")
	}
	if len(cfg.SessionSecret) < 16 {
		return nil, fmt.Errorf("oidc session secret is too short (min 16 chars)")
	}

	scopes := ensureOpenIDScope(cfg.Scopes)
	if len(scopes) == 1 {
		scopes = append(scopes, "profile", "email")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, err
	}

	runtime := &oidcRuntime{
		issuer: cfg.Issuer,
		oauth2Config: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  strings.TrimSpace(cfg.RedirectURL),
			Scopes:       scopes,
		},
		verifier:      provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		sessionSecret: []byte(cfg.SessionSecret),
	}
	return runtime, nil
}

func (a *appServer) authorizeRequest(w http.ResponseWriter, r *http.Request, websocketRequest bool) bool {
	switch a.authMode {
	case authModeNone:
		return true
	case authModeBasic:
		return a.authorizeBasic(w, r)
	case authModeOIDC:
		return a.authorizeOIDC(w, r, websocketRequest)
	default:
		return true
	}
}

func (a *appServer) authorizeBasic(w http.ResponseWriter, r *http.Request) bool {
	if a.isBasicAuthorized(r) {
		return true
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="IncomUdon Relay PWA Client"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return false
}

func (a *appServer) isBasicAuthorized(r *http.Request) bool {
	user, pass, ok := r.BasicAuth()
	if !ok {
		return false
	}
	return secureStringEqual(user, a.basicUser) && secureStringEqual(pass, a.basicPass)
}

func (a *appServer) authorizeOIDC(w http.ResponseWriter, r *http.Request, websocketRequest bool) bool {
	if a.oidc == nil {
		http.Error(w, "oidc runtime unavailable", http.StatusInternalServerError)
		return false
	}

	if _, ok := a.readOIDCSession(r); ok {
		return true
	}

	if websocketRequest {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}

	http.Redirect(w, r, a.oidcLoginURL(r), http.StatusTemporaryRedirect)
	return false
}

func (a *appServer) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	if a.authMode != authModeOIDC || a.oidc == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	next := sanitizeNextPath(r.URL.Query().Get("next"), a.basePath)
	state, err := randomToken(24)
	if err != nil {
		http.Error(w, "failed to create oidc state", http.StatusInternalServerError)
		return
	}
	nonce, err := randomToken(24)
	if err != nil {
		http.Error(w, "failed to create oidc nonce", http.StatusInternalServerError)
		return
	}

	statePayload := oidcStateCookie{
		State: state,
		Nonce: nonce,
		Next:  next,
		Exp:   time.Now().Add(10 * time.Minute).Unix(),
	}
	if err := a.setSignedCookie(w, r, oidcStateCookieName, statePayload, 10*time.Minute, true); err != nil {
		http.Error(w, "failed to persist oidc state", http.StatusInternalServerError)
		return
	}

	oauthCfg := a.oidc.oauth2Config
	oauthCfg.RedirectURL = a.oidcRedirectURL(r)
	authURL := oauthCfg.AuthCodeURL(state, oidc.Nonce(nonce))
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (a *appServer) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if a.authMode != authModeOIDC || a.oidc == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if errText := strings.TrimSpace(r.URL.Query().Get("error")); errText != "" {
		http.Error(w, fmt.Sprintf("oidc authentication failed: %s", errText), http.StatusUnauthorized)
		return
	}

	var stateCookie oidcStateCookie
	if err := a.readSignedCookie(r, oidcStateCookieName, &stateCookie); err != nil {
		http.Error(w, "missing oidc state", http.StatusUnauthorized)
		return
	}
	if stateCookie.Exp < time.Now().Unix() {
		a.clearCookie(w, r, oidcStateCookieName, true)
		http.Error(w, "oidc state expired", http.StatusUnauthorized)
		return
	}
	queryState := strings.TrimSpace(r.URL.Query().Get("state"))
	if !secureStringEqual(queryState, stateCookie.State) {
		a.clearCookie(w, r, oidcStateCookieName, true)
		http.Error(w, "oidc state mismatch", http.StatusUnauthorized)
		return
	}

	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if code == "" {
		a.clearCookie(w, r, oidcStateCookieName, true)
		http.Error(w, "missing oidc code", http.StatusUnauthorized)
		return
	}

	oauthCfg := a.oidc.oauth2Config
	oauthCfg.RedirectURL = a.oidcRedirectURL(r)
	oauthToken, err := oauthCfg.Exchange(r.Context(), code)
	if err != nil {
		a.clearCookie(w, r, oidcStateCookieName, true)
		http.Error(w, "oidc code exchange failed", http.StatusUnauthorized)
		return
	}

	rawIDToken, ok := oauthToken.Extra("id_token").(string)
	if !ok || strings.TrimSpace(rawIDToken) == "" {
		a.clearCookie(w, r, oidcStateCookieName, true)
		http.Error(w, "missing id_token", http.StatusUnauthorized)
		return
	}

	idToken, err := a.oidc.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		a.clearCookie(w, r, oidcStateCookieName, true)
		http.Error(w, "invalid id_token", http.StatusUnauthorized)
		return
	}

	claims := struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
		Name  string `json:"name"`
		Nonce string `json:"nonce"`
		Exp   int64  `json:"exp"`
	}{}
	if err := idToken.Claims(&claims); err != nil {
		a.clearCookie(w, r, oidcStateCookieName, true)
		http.Error(w, "failed to parse id_token claims", http.StatusUnauthorized)
		return
	}
	if claims.Sub == "" {
		a.clearCookie(w, r, oidcStateCookieName, true)
		http.Error(w, "id_token subject is empty", http.StatusUnauthorized)
		return
	}
	if !secureStringEqual(claims.Nonce, stateCookie.Nonce) {
		a.clearCookie(w, r, oidcStateCookieName, true)
		http.Error(w, "oidc nonce mismatch", http.StatusUnauthorized)
		return
	}

	sessionExp := claims.Exp
	if sessionExp <= 0 {
		if !oauthToken.Expiry.IsZero() {
			sessionExp = oauthToken.Expiry.Unix()
		} else {
			sessionExp = time.Now().Add(8 * time.Hour).Unix()
		}
	}
	if sessionExp <= time.Now().Unix() {
		sessionExp = time.Now().Add(5 * time.Minute).Unix()
	}

	sessionPayload := oidcSessionCookie{
		Sub:   claims.Sub,
		Email: claims.Email,
		Name:  claims.Name,
		Exp:   sessionExp,
	}
	ttl := time.Until(time.Unix(sessionExp, 0))
	if ttl < time.Minute {
		ttl = time.Minute
	}
	if ttl > 7*24*time.Hour {
		ttl = 7 * 24 * time.Hour
	}
	if err := a.setSignedCookie(w, r, oidcSessionCookieName, sessionPayload, ttl, true); err != nil {
		a.clearCookie(w, r, oidcStateCookieName, true)
		http.Error(w, "failed to persist session", http.StatusInternalServerError)
		return
	}

	a.clearCookie(w, r, oidcStateCookieName, true)
	http.Redirect(w, r, sanitizeNextPath(stateCookie.Next, a.basePath), http.StatusFound)
}

func (a *appServer) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	switch a.authMode {
	case authModeOIDC:
		if a.oidc != nil {
			a.clearCookie(w, r, oidcSessionCookieName, true)
			a.clearCookie(w, r, oidcStateCookieName, true)
		}
		http.Redirect(w, r, a.homePath(), http.StatusFound)
	case authModeBasic:
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("WWW-Authenticate", `Basic realm="IncomUdon Relay PWA Client (logout)"`)
		http.Error(w, "logged out", http.StatusUnauthorized)
	default:
		http.Redirect(w, r, a.homePath(), http.StatusFound)
	}
}

func (a *appServer) handleAuthCheck(w http.ResponseWriter, r *http.Request) {
	switch a.authMode {
	case authModeNone:
		w.WriteHeader(http.StatusNoContent)
	case authModeBasic:
		if a.isBasicAuthorized(r) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="IncomUdon Relay PWA Client"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	case authModeOIDC:
		if _, ok := a.readOIDCSession(r); ok {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (a *appServer) oidcLoginURL(r *http.Request) string {
	loginPath := a.routePath("/auth/login")
	next := currentRequestURI(r)
	params := url.Values{}
	params.Set("next", next)
	return loginPath + "?" + params.Encode()
}

func (a *appServer) oidcRedirectURL(r *http.Request) string {
	if a.oidc != nil {
		configured := strings.TrimSpace(a.oidc.oauth2Config.RedirectURL)
		if configured != "" {
			return configured
		}
	}

	scheme := "http"
	if isRequestSecure(r) {
		scheme = "https"
	}
	host := requestHost(r)
	if host == "" {
		host = "localhost"
	}
	return fmt.Sprintf("%s://%s%s", scheme, host, a.routePath("/auth/callback"))
}

func (a *appServer) readOIDCSession(r *http.Request) (oidcSessionCookie, bool) {
	var payload oidcSessionCookie
	if a.oidc == nil {
		return payload, false
	}
	if err := a.readSignedCookie(r, oidcSessionCookieName, &payload); err != nil {
		return payload, false
	}
	if payload.Sub == "" || payload.Exp <= time.Now().Unix() {
		return payload, false
	}
	return payload, true
}

func (a *appServer) setSignedCookie(
	w http.ResponseWriter,
	r *http.Request,
	name string,
	payload any,
	ttl time.Duration,
	httpOnly bool,
) error {
	if a.oidc == nil {
		return fmt.Errorf("oidc runtime unavailable")
	}
	token, err := encodeSignedPayload(a.oidc.sessionSecret, payload)
	if err != nil {
		return err
	}
	if ttl <= 0 {
		ttl = time.Minute
	}
	exp := time.Now().Add(ttl)
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    token,
		Path:     a.cookiePath(),
		HttpOnly: httpOnly,
		Secure:   isRequestSecure(r),
		SameSite: http.SameSiteLaxMode,
		Expires:  exp,
		MaxAge:   int(ttl.Seconds()),
	})
	return nil
}

func (a *appServer) readSignedCookie(r *http.Request, name string, out any) error {
	if a.oidc == nil {
		return fmt.Errorf("oidc runtime unavailable")
	}
	cookie, err := r.Cookie(name)
	if err != nil {
		return err
	}
	return decodeSignedPayload(a.oidc.sessionSecret, cookie.Value, out)
}

func (a *appServer) clearCookie(w http.ResponseWriter, r *http.Request, name string, httpOnly bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     a.cookiePath(),
		HttpOnly: httpOnly,
		Secure:   isRequestSecure(r),
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
}

func (a *appServer) cookiePath() string {
	if a.basePath == "" {
		return "/"
	}
	return a.basePath + "/"
}

func (a *appServer) routePath(suffix string) string {
	if a.basePath == "" {
		return suffix
	}
	if suffix == "/" {
		return a.basePath + "/"
	}
	return a.basePath + suffix
}

func (a *appServer) homePath() string {
	return a.routePath("/")
}

func sanitizeNextPath(value string, basePath string) string {
	defaultPath := "/"
	if basePath != "" {
		defaultPath = basePath + "/"
	}

	raw := strings.TrimSpace(value)
	if raw == "" {
		return defaultPath
	}

	parsed, err := url.Parse(raw)
	if err != nil || parsed.IsAbs() {
		return defaultPath
	}

	path := strings.TrimSpace(parsed.Path)
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if strings.HasPrefix(path, "//") {
		return defaultPath
	}

	if basePath != "" {
		basePrefix := basePath + "/"
		if path == "/" || path == basePath {
			path = basePrefix
		} else if !strings.HasPrefix(path, basePrefix) {
			return defaultPath
		}
	}

	if parsed.RawQuery != "" {
		path += "?" + parsed.RawQuery
	}
	return path
}

func currentRequestURI(r *http.Request) string {
	if r == nil || r.URL == nil {
		return "/"
	}
	path := r.URL.Path
	if path == "" {
		path = "/"
	}
	if r.URL.RawQuery != "" {
		path += "?" + r.URL.RawQuery
	}
	return path
}

func requestHost(r *http.Request) string {
	if r == nil {
		return ""
	}
	if headerHost := firstForwardedValue(r.Header.Get("X-Forwarded-Host")); headerHost != "" {
		return headerHost
	}
	return strings.TrimSpace(r.Host)
}

func isRequestSecure(r *http.Request) bool {
	if r == nil {
		return false
	}
	if proto := firstForwardedValue(r.Header.Get("X-Forwarded-Proto")); strings.EqualFold(proto, "https") {
		return true
	}
	return r.TLS != nil
}

func firstForwardedValue(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	if idx := strings.Index(trimmed, ","); idx >= 0 {
		trimmed = trimmed[:idx]
	}
	return strings.TrimSpace(trimmed)
}

func encodeSignedPayload(secret []byte, payload any) (string, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(data)
	signature := mac.Sum(nil)

	dataText := base64.RawURLEncoding.EncodeToString(data)
	sigText := base64.RawURLEncoding.EncodeToString(signature)
	return dataText + "." + sigText, nil
}

func decodeSignedPayload(secret []byte, token string, out any) error {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return fmt.Errorf("invalid signed token format")
	}

	data, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("invalid signed token payload")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("invalid signed token signature")
	}

	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(data)
	expected := mac.Sum(nil)
	if !hmac.Equal(signature, expected) {
		return fmt.Errorf("signed token verification failed")
	}

	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("invalid signed token json: %w", err)
	}
	return nil
}

func randomToken(byteLen int) (string, error) {
	if byteLen <= 0 {
		byteLen = 16
	}
	buf := make([]byte, byteLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func secureStringEqual(a string, b string) bool {
	sumA := sha256.Sum256([]byte(a))
	sumB := sha256.Sum256([]byte(b))
	if subtle.ConstantTimeCompare(sumA[:], sumB[:]) != 1 {
		return false
	}
	return len(a) == len(b)
}

func authenticateWebSocketRequest(r *http.Request, expectedToken string) bool {
	if strings.TrimSpace(expectedToken) == "" {
		return true
	}
	token := extractWebSocketToken(r)
	if token == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) == 1
}

func extractWebSocketToken(r *http.Request) string {
	query := r.URL.Query()
	if token := strings.TrimSpace(query.Get("token")); token != "" {
		return token
	}
	if token := strings.TrimSpace(query.Get("ws_token")); token != "" {
		return token
	}
	if token := strings.TrimSpace(r.Header.Get("X-Incomudon-WS-Token")); token != "" {
		return token
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(auth) >= len("bearer ") && strings.EqualFold(auth[:len("bearer ")], "bearer ") {
		return strings.TrimSpace(auth[len("bearer "):])
	}
	return ""
}

func parseRelayTarget(cmd clientCommand) (string, int, error) {
	host := strings.TrimSpace(cmd.RelayHost)
	port := cmd.RelayPort

	address := strings.TrimSpace(cmd.RelayAddress)
	if address != "" {
		h, p, err := splitHostPort(address)
		if err != nil {
			return "", 0, fmt.Errorf("invalid relayAddress: %v", err)
		}
		host = h
		if p != 0 {
			port = p
		}
	}

	if host == "" {
		host = "127.0.0.1"
	}
	if port == 0 {
		port = 50000
	}
	if port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("relay port is out of range")
	}

	return host, port, nil
}

func parseFixedRelayConfig(value string) (string, int, bool, error) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return "", 0, false, nil
	}

	host, port, err := splitHostPort(raw)
	if err != nil {
		return "", 0, false, err
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", 0, false, fmt.Errorf("relay host is empty")
	}

	if port == 0 {
		port = 50000
	}
	if port <= 0 || port > 65535 {
		return "", 0, false, fmt.Errorf("relay port is out of range")
	}

	return host, port, true, nil
}

func redirectWithQuery(w http.ResponseWriter, r *http.Request, target string) {
	query := strings.TrimSpace(r.URL.RawQuery)
	if query != "" {
		if strings.Contains(target, "?") {
			target += "&" + query
		} else {
			target += "?" + query
		}
	}
	http.Redirect(w, r, target, http.StatusTemporaryRedirect)
}

func splitHostPort(value string) (string, int, error) {
	if strings.Contains(value, ":") {
		host, portText, err := net.SplitHostPort(value)
		if err == nil {
			port, convErr := strconv.Atoi(portText)
			if convErr != nil {
				return "", 0, convErr
			}
			return host, port, nil
		}

		if strings.Contains(err.Error(), "missing port in address") {
			return value, 0, nil
		}

		if strings.Count(value, ":") > 1 && !strings.HasPrefix(value, "[") {
			// Probably a raw IPv6 address without port.
			return value, 0, nil
		}
		return "", 0, err
	}

	return value, 0, nil
}

func randomSenderID() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 1
	}
	id := binary.BigEndian.Uint32(b[:]) & 0x7FFFFFFF
	if id == 0 {
		id = 1
	}
	return id
}
