// Command agent is the ZTNA client agent that runs on the user's device.
// It authenticates with email/password, receives a WireGuard config, and
// establishes a tunnel to the nearest PoP.
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
	"syscall"
	"time"
)

// AgentConfig holds the client agent configuration.
type AgentConfig struct {
	ControlPlaneURL string
	Email           string
	Password        string
	Token           string // JWT obtained after login
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
	email := flag.String("email", "", "Email de l'utilisateur")
	password := flag.String("password", "", "Mot de passe de l'utilisateur")
	deviceName := flag.String("device", "", "Nom de l'appareil (defaut: hostname)")
	wgInterface := flag.String("wg-interface", "wg-ztna", "Nom de l'interface WireGuard")
	flag.Parse()

	if *email == "" || *password == "" {
		fmt.Println("╔══════════════════════════════════════════════╗")
		fmt.Println("║    ZTNA Sovereign - Agent Client             ║")
		fmt.Println("╚══════════════════════════════════════════════╝")
		fmt.Println()
		fmt.Println("Usage:")
		fmt.Println("  ztna-agent --email <EMAIL> --password <MOT_DE_PASSE> --control-plane <URL>")
		fmt.Println()
		fmt.Println("Options:")
		fmt.Println("  --email          Email de votre compte ZTNA")
		fmt.Println("  --password       Mot de passe de votre compte")
		fmt.Println("  --control-plane  URL du Control Plane (defaut: http://localhost:8080)")
		fmt.Println("  --device         Nom de cet appareil (defaut: hostname)")
		fmt.Println("  --wg-interface   Nom de l'interface WireGuard (defaut: wg-ztna)")
		fmt.Println()
		fmt.Println("Exemple:")
		fmt.Printf("  ztna-agent --email admin@monentreprise.fr --password MonMotDePasse --control-plane http://176.136.202.205:8080\n")
		os.Exit(1)
	}

	if *deviceName == "" {
		hostname, _ := os.Hostname()
		*deviceName = hostname
	}

	logger := log.New(os.Stdout, "[ZTNA Agent] ", log.LstdFlags)

	logger.Println("══════════════════════════════════════════════")
	logger.Println("  ZTNA Sovereign - Agent Client")
	logger.Printf("  Appareil : %s (%s/%s)", *deviceName, runtime.GOOS, runtime.GOARCH)
	logger.Printf("  Control Plane : %s", *controlPlane)
	logger.Printf("  Utilisateur : %s", *email)
	logger.Println("══════════════════════════════════════════════")

	config := AgentConfig{
		ControlPlaneURL: *controlPlane,
		Email:           *email,
		Password:        *password,
		DeviceName:      *deviceName,
		WGInterface:     *wgInterface,
	}

	// Step 1: Authenticate with email/password
	logger.Println("[1/3] Authentification en cours...")
	loginResp, err := login(config)
	if err != nil {
		logger.Fatalf("Echec authentification : %v", err)
	}
	config.Token = loginResp.Token
	logger.Printf("  Authentifie : %s (%s)", loginResp.User.Name, loginResp.User.Email)

	// Step 2: Register agent and get WireGuard config
	logger.Println("[2/3] Enregistrement de l'agent...")
	regResp, err := registerAgent(config)
	if err != nil {
		logger.Fatalf("Echec enregistrement : %v", err)
	}
	logger.Printf("  Agent ID : %s", regResp.AgentID)
	logger.Printf("  IP Tunnel : %s", regResp.TunnelIP)

	// Step 3: Apply WireGuard configuration
	logger.Println("[3/3] Configuration du tunnel WireGuard...")
	if err := applyWireGuardConfig(config.WGInterface, regResp.ConfigINI, logger); err != nil {
		logger.Printf("ATTENTION : Echec configuration WireGuard : %v", err)
		logger.Println("Configuration a appliquer manuellement :")
		logger.Println("---")
		logger.Println(regResp.ConfigINI)
		logger.Println("---")
		if runtime.GOOS == "windows" {
			logger.Println("Assurez-vous que WireGuard pour Windows est installe :")
			logger.Println("  https://www.wireguard.com/install/")
		}
	} else {
		logger.Println("  Tunnel WireGuard etabli !")
	}

	logger.Println()
	logger.Println("══════════════════════════════════════════════")
	logger.Println("  CONNECTE au reseau ZTNA")
	logger.Printf("  IP Tunnel : %s", regResp.TunnelIP)
	logger.Println("  Appuyez sur Ctrl+C pour deconnecter")
	logger.Println("══════════════════════════════════════════════")

	go monitorConnection(config, logger)

	// Wait for shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	// Cleanup
	logger.Println()
	logger.Println("Deconnexion...")
	teardownWireGuard(config.WGInterface, logger)
	logger.Println("Deconnecte du reseau ZTNA. A bientot !")
}

// login authenticates with the Control Plane and returns a JWT token.
func login(config AgentConfig) (*LoginResponse, error) {
	reqBody := map[string]string{
		"email":    config.Email,
		"password": config.Password,
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

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
		return nil, fmt.Errorf("compte desactive, contactez votre administrateur")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("erreur serveur (code %d): %s", resp.StatusCode, string(body))
	}

	var result LoginResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("reponse invalide du serveur: %w", err)
	}

	if result.Token == "" {
		return nil, fmt.Errorf("pas de token recu du serveur")
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

	data, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/api/agent/register", config.ControlPlaneURL)
	resp, err := http.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("impossible de contacter le Control Plane: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("session expiree, relancez l'agent")
	}
	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("erreur enregistrement (code %d): %s", resp.StatusCode, string(body))
	}

	var result RegistrationResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("reponse invalide: %w", err)
	}

	return &result, nil
}

// applyWireGuardConfig applies the WireGuard configuration on the local system.
func applyWireGuardConfig(iface string, configINI string, logger *log.Logger) error {
	if configINI == "" {
		return fmt.Errorf("aucune configuration WireGuard recue (aucun PoP disponible ?)")
	}

	switch runtime.GOOS {
	case "linux":
		return applyWireGuardLinux(iface, configINI)
	case "windows":
		return applyWireGuardWindows(iface, configINI, logger)
	case "darwin":
		return applyWireGuardDarwin(iface, configINI, logger)
	default:
		return fmt.Errorf("OS non supporte: %s", runtime.GOOS)
	}
}

func applyWireGuardLinux(iface string, configINI string) error {
	configPath := fmt.Sprintf("/etc/wireguard/%s.conf", iface)
	if err := os.WriteFile(configPath, []byte(configINI), 0600); err != nil {
		return fmt.Errorf("impossible d'ecrire la config: %w (lancez avec sudo)", err)
	}
	cmd := exec.Command("wg-quick", "up", iface)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("wg-quick up echoue: %s: %w", string(output), err)
	}
	return nil
}

func applyWireGuardWindows(iface string, configINI string, logger *log.Logger) error {
	// On Windows, use the WireGuard tunnel service
	configDir := `C:\ProgramData\WireGuard`
	configPath := fmt.Sprintf(`%s\%s.conf`, configDir, iface)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		logger.Printf("Impossible de creer le dossier WireGuard: %v", err)
	}
	if err := os.WriteFile(configPath, []byte(configINI), 0600); err != nil {
		return fmt.Errorf("impossible d'ecrire la config: %w (lancez en Administrateur)", err)
	}

	logger.Printf("  Config ecrite dans : %s", configPath)

	// Try to use wireguard.exe CLI
	cmd := exec.Command("wireguard.exe", "/installtunnelservice", configPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		// Fallback: try wg-quick if available
		cmd2 := exec.Command("wg-quick", "up", configPath)
		if output2, err2 := cmd2.CombinedOutput(); err2 != nil {
			logger.Printf("wireguard.exe echoue: %s", string(output))
			logger.Printf("wg-quick echoue: %s", string(output2))
			logger.Println()
			logger.Println("Importez manuellement la config dans WireGuard pour Windows :")
			logger.Printf("  Fichier : %s", configPath)
			return fmt.Errorf("WireGuard non trouve. Installez-le depuis https://www.wireguard.com/install/")
		}
	}
	return nil
}

func applyWireGuardDarwin(iface string, configINI string, logger *log.Logger) error {
	configPath := fmt.Sprintf("/usr/local/etc/wireguard/%s.conf", iface)
	_ = os.MkdirAll("/usr/local/etc/wireguard", 0755)
	if err := os.WriteFile(configPath, []byte(configINI), 0600); err != nil {
		return fmt.Errorf("impossible d'ecrire la config: %w", err)
	}
	cmd := exec.Command("wg-quick", "up", iface)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("wg-quick up echoue: %s: %w", string(output), err)
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
	logger.Println("Tunnel WireGuard ferme")
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
				logger.Println("ATTENTION : Tunnel WireGuard semble inactif")
			}
		case "windows":
			// Check if the interface exists
			cmd := exec.Command("netsh", "interface", "show", "interface", config.WGInterface)
			if err := cmd.Run(); err != nil {
				logger.Println("ATTENTION : Interface WireGuard non trouvee")
			}
		}
	}
}
