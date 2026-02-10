// Command agent is the ZTNA client agent with a graphical web-based interface.
// Double-click the executable to open the futuristic GUI in your browser.
// Use --cli mode for headless/terminal usage.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// AgentConfig holds the client agent configuration.
type AgentConfig struct {
	ControlPlaneURL string
	Email           string
	Password        string
	Token           string
	DeviceName      string
	WGInterface     string
}

// LoginResponse is returned by /api/auth/login.
type LoginResponse struct {
	Token string `json:"token"`
	User  struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Name  string `json:"name"`
		Role  string `json:"role"`
	} `json:"user"`
}

// RegistrationResponse is the response from the Control Plane after registration.
type RegistrationResponse struct {
	AgentID   string `json:"agent_id"`
	TunnelIP  string `json:"tunnel_ip"`
	ConfigINI string `json:"config_ini"`
}

func main() {
	controlPlane := flag.String("control-plane", "http://localhost:8080", "URL du Control Plane")
	email := flag.String("email", "", "Email (mode CLI uniquement)")
	password := flag.String("password", "", "Mot de passe (mode CLI uniquement)")
	deviceName := flag.String("device", "", "Nom de l'appareil")
	wgInterface := flag.String("wg-interface", "wg-ztna", "Interface WireGuard")
	cliMode := flag.Bool("cli", false, "Mode ligne de commande (sans interface graphique)")
	flag.Parse()

	if *deviceName == "" {
		hostname, _ := os.Hostname()
		*deviceName = hostname
	}

	logger := log.New(os.Stdout, "[ZTNA] ", log.LstdFlags)

	// CLI mode: original behavior
	if *cliMode {
		runCLI(*controlPlane, *email, *password, *deviceName, *wgInterface, logger)
		return
	}

	// GUI mode (default): start local web server + open browser
	logger.Println("══════════════════════════════════════════════")
	logger.Println("  ZTNA Sovereign — Agent Client")
	logger.Printf("  Mode : Interface graphique")
	logger.Printf("  Appareil : %s (%s/%s)", *deviceName, runtime.GOOS, runtime.GOARCH)
	logger.Println("══════════════════════════════════════════════")

	gui := NewGUIServer(*controlPlane, *deviceName, *wgInterface, logger)
	if err := gui.Start(); err != nil {
		logger.Fatalf("Erreur serveur GUI: %v", err)
	}
}

// runCLI runs the agent in CLI (headless) mode.
func runCLI(controlPlane, email, password, deviceName, wgInterface string, logger *log.Logger) {
	if email == "" || password == "" {
		fmt.Println("Mode CLI : --email et --password sont requis")
		fmt.Println("Usage: ztna-agent --cli --email <EMAIL> --password <MOT_DE_PASSE> --control-plane <URL>")
		os.Exit(1)
	}

	logger.Println("══════════════════════════════════════════════")
	logger.Println("  ZTNA Sovereign — Agent Client (CLI)")
	logger.Printf("  Appareil : %s (%s/%s)", deviceName, runtime.GOOS, runtime.GOARCH)
	logger.Printf("  Control Plane : %s", controlPlane)
	logger.Printf("  Utilisateur : %s", email)
	logger.Println("══════════════════════════════════════════════")

	config := AgentConfig{
		ControlPlaneURL: controlPlane,
		Email:           email,
		Password:        password,
		DeviceName:      deviceName,
		WGInterface:     wgInterface,
	}

	// Step 1: Login
	logger.Println("[1/3] Authentification...")
	loginResp, err := login(config)
	if err != nil {
		logger.Fatalf("Echec : %v", err)
	}
	config.Token = loginResp.Token
	logger.Printf("  OK : %s (%s)", loginResp.User.Name, loginResp.User.Email)

	// Step 2: Register
	logger.Println("[2/3] Enregistrement...")
	regResp, err := registerAgent(config)
	if err != nil {
		logger.Fatalf("Echec : %v", err)
	}
	logger.Printf("  ID : %s / IP : %s", regResp.AgentID, regResp.TunnelIP)

	// Step 3: WireGuard
	logger.Println("[3/3] Tunnel WireGuard...")
	if err := applyWireGuardConfig(config.WGInterface, regResp.ConfigINI, logger); err != nil {
		logger.Printf("ATTENTION : %v", err)
	} else {
		logger.Println("  Tunnel etabli !")
	}

	logger.Println()
	logger.Println("CONNECTE — Ctrl+C pour deconnecter")

	go monitorConnection(config, logger)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Println("Deconnexion...")
	teardownWireGuard(config.WGInterface, logger)
}

// login authenticates with the Control Plane and returns a JWT token.
func login(config AgentConfig) (*LoginResponse, error) {
	reqBody := map[string]string{
		"email":    config.Email,
		"password": config.Password,
	}
	data, _ := json.Marshal(reqBody)

	url := fmt.Sprintf("%s/api/auth/login", config.ControlPlaneURL)
	resp, err := http.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("impossible de contacter le Control Plane: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("email ou mot de passe incorrect")
	}
	if resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("compte désactivé")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("erreur serveur (%d): %s", resp.StatusCode, string(body))
	}

	var result LoginResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("réponse invalide: %w", err)
	}
	if result.Token == "" {
		return nil, fmt.Errorf("pas de token reçu")
	}
	return &result, nil
}

// registerAgent sends a registration request to the Control Plane.
func registerAgent(config AgentConfig) (*RegistrationResponse, error) {
	reqBody := map[string]string{
		"token":       config.Token,
		"device_name": config.DeviceName,
		"os":          runtime.GOOS,
	}
	data, _ := json.Marshal(reqBody)

	url := fmt.Sprintf("%s/api/agent/register", config.ControlPlaneURL)
	resp, err := http.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("impossible de contacter le Control Plane: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("erreur enregistrement (%d): %s", resp.StatusCode, string(body))
	}

	var result RegistrationResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("réponse invalide: %w", err)
	}
	return &result, nil
}

// applyWireGuardConfig applies the WireGuard configuration on the local system.
func applyWireGuardConfig(iface string, configINI string, logger *log.Logger) error {
	if configINI == "" {
		return fmt.Errorf("aucune configuration WireGuard reçue (aucun PoP disponible ?)")
	}
	switch runtime.GOOS {
	case "linux":
		return applyWireGuardLinux(iface, configINI)
	case "windows":
		return applyWireGuardWindows(iface, configINI, logger)
	case "darwin":
		return applyWireGuardDarwin(iface, configINI, logger)
	default:
		return fmt.Errorf("OS non supporté: %s", runtime.GOOS)
	}
}

func applyWireGuardLinux(iface string, configINI string) error {
	configPath := fmt.Sprintf("/etc/wireguard/%s.conf", iface)
	if err := os.WriteFile(configPath, []byte(configINI), 0600); err != nil {
		return fmt.Errorf("impossible d'écrire la config: %w (lancez avec sudo)", err)
	}
	cmd := exec.Command("wg-quick", "up", iface)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("wg-quick échoué: %s: %w", string(output), err)
	}
	return nil
}

func applyWireGuardWindows(iface string, configINI string, logger *log.Logger) error {
	// Check if WireGuard is installed
	wgPaths := []string{
		`C:\Program Files\WireGuard\wireguard.exe`,
		`C:\Program Files (x86)\WireGuard\wireguard.exe`,
	}
	wgFound := false
	var wgPath string
	for _, path := range wgPaths {
		if _, err := os.Stat(path); err == nil {
			wgFound = true
			wgPath = path
			break
		}
	}

	// Also check if wg-quick is in PATH
	if !wgFound {
		if path, err := exec.LookPath("wg-quick"); err == nil {
			wgFound = true
			wgPath = path
		}
	}

	if !wgFound {
		// Try to install automatically
		if runtime.GOOS == "windows" {
			if err := installWireGuardAutomatically(logger); err != nil {
				return fmt.Errorf("WireGuard n'est pas installé et l'installation automatique a échoué: %v. Installez-le manuellement depuis https://www.wireguard.com/install/", err)
			}
			// Re-check after installation
			if !isWireGuardInstalled() {
				return fmt.Errorf("WireGuard installé mais non détecté. Redémarrez l'agent.")
			}
			// Update wgPath
			for _, path := range wgPaths {
				if _, err := os.Stat(path); err == nil {
					wgFound = true
					wgPath = path
					break
				}
			}
		} else {
			return fmt.Errorf("WireGuard n'est pas installé. Installez-le depuis https://www.wireguard.com/install/")
		}
	}

	configDir := `C:\ProgramData\WireGuard`
	configPath := fmt.Sprintf(`%s\%s.conf`, configDir, iface)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		logger.Printf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(configPath, []byte(configINI), 0600); err != nil {
		return fmt.Errorf("impossible d'écrire la config: %w (lancez en Administrateur)", err)
	}
	logger.Printf("Config WireGuard écrite: %s", configPath)

	// Try wireguard.exe service first
	if strings.Contains(wgPath, "wireguard.exe") {
		cmd := exec.Command(wgPath, "/installtunnelservice", configPath)
		if output, err := cmd.CombinedOutput(); err != nil {
			logger.Printf("wireguard.exe échoué: %s", string(output))
			// Fallback: try wg-quick
			if path, err := exec.LookPath("wg-quick"); err == nil {
				cmd2 := exec.Command(path, "up", configPath)
				if output2, err2 := cmd2.CombinedOutput(); err2 != nil {
					return fmt.Errorf("échec installation tunnel: %s. Vérifiez que WireGuard est bien installé et que vous êtes Administrateur", string(output2))
				}
			} else {
				return fmt.Errorf("échec installation tunnel WireGuard. Vérifiez que WireGuard est bien installé et que vous êtes Administrateur")
			}
		} else {
			logger.Println("Tunnel WireGuard installé avec succès")
		}
	} else {
		// Use wg-quick
		cmd := exec.Command(wgPath, "up", configPath)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("wg-quick échoué: %s: %w", string(output), err)
		}
		logger.Println("Tunnel WireGuard activé avec wg-quick")
	}
	return nil
}

func applyWireGuardDarwin(iface string, configINI string, logger *log.Logger) error {
	configPath := fmt.Sprintf("/usr/local/etc/wireguard/%s.conf", iface)
	_ = os.MkdirAll("/usr/local/etc/wireguard", 0755)
	if err := os.WriteFile(configPath, []byte(configINI), 0600); err != nil {
		return fmt.Errorf("impossible d'écrire la config: %w", err)
	}
	cmd := exec.Command("wg-quick", "up", iface)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("wg-quick échoué: %s: %w", string(output), err)
	}
	return nil
}

// teardownWireGuard removes the WireGuard tunnel.
func teardownWireGuard(iface string, logger *log.Logger) {
	switch runtime.GOOS {
	case "linux", "darwin":
		exec.Command("wg-quick", "down", iface).Run()
	case "windows":
		exec.Command("wireguard.exe", "/uninstalltunnelservice", iface).Run()
		configPath := fmt.Sprintf(`C:\ProgramData\WireGuard\%s.conf`, iface)
		os.Remove(configPath)
	}
	logger.Println("Tunnel WireGuard fermé")
}

// monitorConnection periodically checks tunnel health.
func monitorConnection(config AgentConfig, logger *log.Logger) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		switch runtime.GOOS {
		case "linux":
			cmd := exec.Command("wg", "show", config.WGInterface)
			if err := cmd.Run(); err != nil {
				logger.Println("ATTENTION : Tunnel inactif")
			}
		case "windows":
			cmd := exec.Command("netsh", "interface", "show", "interface", config.WGInterface)
			if err := cmd.Run(); err != nil {
				logger.Println("ATTENTION : Interface WireGuard non trouvée")
			}
		}
	}
}
