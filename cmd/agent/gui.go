package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"sync"
	"time"
)

//go:embed ui/index.html
var uiFS embed.FS

// GUIServer is the local web server that serves the agent GUI.
type GUIServer struct {
	mu           sync.Mutex
	logger       *log.Logger
	controlPlane string
	connected    bool
	tunnelIP     string
	agentID      string
	email        string
	deviceName   string
	wgInterface  string
	connectedAt  time.Time
	configINI    string
}

// ConnectRequest is the request body from the GUI.
type ConnectRequest struct {
	Email        string `json:"email"`
	Password     string `json:"password"`
	ControlPlane string `json:"control_plane"`
}

// ConnectResponse is returned to the GUI after successful connection.
type ConnectResponse struct {
	Connected    bool   `json:"connected"`
	TunnelIP     string `json:"tunnel_ip"`
	AgentID      string `json:"agent_id"`
	Email        string `json:"email"`
	Device       string `json:"device"`
	ControlPlane string `json:"control_plane"`
	Warning      string `json:"warning,omitempty"` // Warning if WireGuard setup failed
}

// NewGUIServer creates a new GUI server.
func NewGUIServer(controlPlane, deviceName, wgInterface string, logger *log.Logger) *GUIServer {
	return &GUIServer{
		logger:       logger,
		controlPlane: controlPlane,
		deviceName:   deviceName,
		wgInterface:  wgInterface,
	}
}

// Start starts the local GUI server and opens the browser.
func (s *GUIServer) Start() error {
	// Find an available port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("impossible de démarrer le serveur local: %w", err)
	}

	port := listener.Addr().(*net.TCPAddr).Port
	url := fmt.Sprintf("http://127.0.0.1:%d", port)

	mux := http.NewServeMux()

	// Serve the embedded UI
	mux.HandleFunc("GET /", s.handleUI)
	mux.HandleFunc("POST /api/connect", s.handleConnect)
	mux.HandleFunc("POST /api/disconnect", s.handleDisconnect)
	mux.HandleFunc("GET /api/status", s.handleStatus)
	mux.HandleFunc("GET /api/info", s.handleInfo)

	server := &http.Server{Handler: mux}

	s.logger.Printf("Interface graphique démarrée : %s", url)
	s.logger.Println("Ouverture du navigateur...")

	// Open browser
	go func() {
		time.Sleep(300 * time.Millisecond)
		openBrowser(url)
	}()

	return server.Serve(listener)
}

// handleUI serves the embedded HTML file.
func (s *GUIServer) handleUI(w http.ResponseWriter, r *http.Request) {
	data, err := uiFS.ReadFile("ui/index.html")
	if err != nil {
		http.Error(w, "UI not found", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

// handleInfo returns the default control plane URL.
func (s *GUIServer) handleInfo(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	cp := s.controlPlane
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"control_plane": cp,
	})
}

// handleStatus returns the current connection status.
func (s *GUIServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ConnectResponse{
		Connected:    s.connected,
		TunnelIP:     s.tunnelIP,
		AgentID:      s.agentID,
		Email:        s.email,
		Device:       s.deviceName,
		ControlPlane: s.controlPlane,
	})
}

// handleConnect authenticates and establishes the WireGuard tunnel.
func (s *GUIServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	var req ConnectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, 400, "Requête invalide")
		return
	}

	if req.Email == "" || req.Password == "" {
		jsonErr(w, 400, "Email et mot de passe requis")
		return
	}

	cp := req.ControlPlane
	if cp == "" {
		cp = s.controlPlane
	}

	s.logger.Printf("Connexion en cours pour %s vers %s...", req.Email, cp)

	// Step 1: Login to get JWT
	config := AgentConfig{
		ControlPlaneURL: cp,
		Email:           req.Email,
		Password:        req.Password,
		DeviceName:      s.deviceName,
		WGInterface:     s.wgInterface,
	}

	loginResp, err := login(config)
	if err != nil {
		s.logger.Printf("Échec authentification: %v", err)
		jsonErr(w, 401, fmt.Sprintf("Authentification échouée : %s", err.Error()))
		return
	}

	config.Token = loginResp.Token
	s.logger.Printf("Authentifié: %s (%s)", loginResp.User.Name, loginResp.User.Email)

	// Step 2: Register agent
	regResp, err := registerAgent(config)
	if err != nil {
		s.logger.Printf("Échec enregistrement: %v", err)
		jsonErr(w, 500, fmt.Sprintf("Enregistrement échoué : %s", err.Error()))
		return
	}

	s.logger.Printf("Agent enregistré: ID=%s, IP=%s", regResp.AgentID, regResp.TunnelIP)

	// Step 3: Apply WireGuard config
	var wgWarning string
	if regResp.ConfigINI != "" {
		if err := applyWireGuardConfig(config.WGInterface, regResp.ConfigINI, s.logger); err != nil {
			s.logger.Printf("WireGuard: %v", err)
			wgWarning = err.Error()
			// Don't fail - the tunnel might need manual setup but connection is established
		} else {
			s.logger.Println("Tunnel WireGuard établi !")
		}
	}

	// Update state
	s.mu.Lock()
	s.connected = true
	s.tunnelIP = regResp.TunnelIP
	s.agentID = regResp.AgentID
	s.email = req.Email
	s.controlPlane = cp
	s.configINI = regResp.ConfigINI
	s.connectedAt = time.Now()
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ConnectResponse{
		Connected:    true,
		TunnelIP:     regResp.TunnelIP,
		AgentID:      regResp.AgentID,
		Email:        req.Email,
		Device:       s.deviceName,
		ControlPlane: cp,
		Warning:      wgWarning,
	})
}

// handleDisconnect tears down the WireGuard tunnel.
func (s *GUIServer) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	wasConnected := s.connected
	iface := s.wgInterface
	s.connected = false
	s.tunnelIP = ""
	s.agentID = ""
	s.mu.Unlock()

	if wasConnected {
		teardownWireGuard(iface, s.logger)
		s.logger.Println("Tunnel déconnecté")
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"disconnected": true})
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// openBrowser opens the default browser to the given URL.
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		// Try common Linux browsers
		for _, browser := range []string{"xdg-open", "sensible-browser", "x-www-browser", "firefox", "google-chrome"} {
			if path, err := exec.LookPath(browser); err == nil {
				cmd = exec.Command(path, url)
				break
			}
		}
	}
	if cmd != nil {
		_ = cmd.Start()
		// Don't wait - let it run in the background
		go func() {
			_ = cmd.Wait()
		}()
	}
}

// readBody reads and returns the body as string (helper).
func readBody(r *http.Request) string {
	data, _ := io.ReadAll(r.Body)
	return string(data)
}
