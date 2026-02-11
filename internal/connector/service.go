// Package connector implements the site connector service that runs on the
// client's internal network. It establishes an outbound WireGuard tunnel to the
// PoP and exposes internal resources.
package connector

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ztna-sovereign/ztna/internal/models"
	"github.com/ztna-sovereign/ztna/internal/wireguard"
)

// Config holds the site connector configuration.
type Config struct {
	ControlPlaneURL string   `json:"control_plane_url"`
	Token           string   `json:"token"`        // Activation token from Control Plane
	ConnectorID     string   `json:"connector_id"` // Set after registration
	WGInterface     string   `json:"wg_interface"`
	Networks        []string `json:"networks"` // Internal networks to expose
	HeartbeatSec    int      `json:"heartbeat_sec"`
}

// Service is the site connector service.
type Service struct {
	config   Config
	logger   *log.Logger
	wgConfig *models.WireGuardConfig
	running  bool
}

// NewService creates a new site connector service.
func NewService(cfg Config, logger *log.Logger) *Service {
	if cfg.WGInterface == "" {
		cfg.WGInterface = "wg-connector"
	}
	if cfg.HeartbeatSec == 0 {
		cfg.HeartbeatSec = 30
	}

	return &Service{
		config: cfg,
		logger: logger,
	}
}

// Start begins the site connector: registers with Control Plane, configures WireGuard,
// and starts the heartbeat loop.
func (s *Service) Start() error {
	s.logger.Println("Starting site connector...")

	// Step 1: Register with Control Plane
	if err := s.register(); err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}

	// Step 2: Configure WireGuard tunnel
	if err := s.setupWireGuard(); err != nil {
		s.logger.Printf("WARNING: WireGuard setup failed: %v (continuing without WG)", err)
	}

	// Step 3: Enable IP forwarding for internal network access
	if err := s.enableForwarding(); err != nil {
		s.logger.Printf("WARNING: IP forwarding setup failed: %v", err)
	}

	// Step 4: Start heartbeat loop
	s.running = true
	go s.heartbeatLoop()

	// Step 5: Start traffic monitoring (optional, logs to syslog)
	if runtime.GOOS == "linux" {
		go s.monitorTraffic()
	}

	s.logger.Println("Site connector started successfully")
	s.logger.Printf("Connector ID: %s", s.config.ConnectorID)
	s.logger.Printf("Exposing networks: %v", s.config.Networks)
	s.logger.Println("")
	s.logger.Println("📊 Pour voir les logs de trafic :")
	s.logger.Println("   - journalctl -k -f | grep ZTNA-CONNECTOR")
	s.logger.Println("   - ou: tail -f /var/log/kern.log | grep ZTNA-CONNECTOR")
	s.logger.Println("")
	s.logger.Println("🔍 Pour vérifier que les règles iptables LOG sont actives :")
	s.logger.Println("   sudo iptables -L FORWARD -n -v | grep LOG")
	s.logger.Println("")
	s.logger.Println("📈 Pour voir les statistiques WireGuard :")
	s.logger.Println("   sudo wg show wg-connector")

	return nil
}

// Stop gracefully stops the site connector.
func (s *Service) Stop() {
	s.running = false

	// Tear down WireGuard interface
	if runtime.GOOS == "linux" {
		exec.Command("ip", "link", "del", "dev", s.config.WGInterface).Run()
	}

	s.logger.Println("Site connector stopped")
}

// register sends the activation token to the Control Plane and receives the WireGuard config.
func (s *Service) register() error {
	// Try to load existing keys from file (for reconnection after restart)
	var keyPair *wireguard.KeyPair
	savedKeys, err := s.loadKeys()
	if err != nil {
		// No existing keys - generate new ones
		keyPair, err = wireguard.GenerateKeyPair()
		if err != nil {
			return fmt.Errorf("failed to generate keys: %w", err)
		}
		s.logger.Println("Nouvelles cles generees (premiere activation)")
	} else {
		// Use saved keys
		keyPair = &savedKeys
		s.logger.Println("Cles existantes chargees depuis le fichier")
	}

	reqBody := map[string]string{
		"token":      s.config.Token,
		"public_key": keyPair.PublicKey,
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/api/connector/register", s.config.ControlPlaneURL)
	resp, err := http.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("registration request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("registration failed with status %d", resp.StatusCode)
	}

	var result struct {
		ConnectorID string                 `json:"connector_id"`
		PublicKey   string                 `json:"public_key"`
		Config      models.WireGuardConfig `json:"config"`
		ConfigINI   string                 `json:"config_ini"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to parse registration response: %w", err)
	}

	s.config.ConnectorID = result.ConnectorID
	s.wgConfig = &result.Config

	// Save the API-returned keys for reuse on restart
	// The API generates the actual keypair; we must save THOSE keys (not our local ones)
	// so on reconnection the public key matches what the API has stored
	if result.PublicKey != "" && s.wgConfig != nil && s.wgConfig.PrivateKey != "" {
		apiKeyPair := wireguard.KeyPair{
			PublicKey:  result.PublicKey,
			PrivateKey: s.wgConfig.PrivateKey,
		}
		if err := s.saveKeys(apiKeyPair); err != nil {
			s.logger.Printf("WARNING: failed to save API keys: %v", err)
		}
		s.logger.Printf("Saved API-generated keys (pub: %s...)", result.PublicKey[:16])
	} else {
		if err := s.saveKeys(*keyPair); err != nil {
			s.logger.Printf("WARNING: failed to save keys: %v", err)
		}
	}

	s.logger.Printf("Registered with Control Plane as connector %s", s.config.ConnectorID)
	return nil
}

// setupWireGuard configures the outbound WireGuard tunnel to the PoP.
func (s *Service) setupWireGuard() error {
	if s.wgConfig == nil {
		return fmt.Errorf("no WireGuard config received from Control Plane")
	}

	if runtime.GOOS != "linux" {
		s.logger.Println("WireGuard kernel module only available on Linux. Printing config instead:")
		s.logger.Println(wireguard.RenderINI(s.wgConfig))
		return nil
	}

	// Write config to temp file
	configINI := wireguard.RenderINI(s.wgConfig)
	configPath := fmt.Sprintf("/etc/wireguard/%s.conf", s.config.WGInterface)

	if err := writeFile(configPath, configINI); err != nil {
		return fmt.Errorf("failed to write WG config: %w", err)
	}

	// If interface already exists (e.g. previous run), bring it down first so wg-quick up can succeed
	downCmd := exec.Command("wg-quick", "down", s.config.WGInterface)
	if output, err := downCmd.CombinedOutput(); err != nil {
		// Ignore error: interface may not exist yet
		s.logger.Printf("wg-quick down %s (optional): %s", s.config.WGInterface, string(output))
	} else {
		s.logger.Printf("wg-quick down %s: interface removed, will bring up with new config", s.config.WGInterface)
	}

	// Bring up the interface using wg-quick
	cmd := exec.Command("wg-quick", "up", s.config.WGInterface)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("wg-quick up failed: %s: %w", string(output), err)
	}

	s.logger.Printf("WireGuard tunnel %s established to PoP", s.config.WGInterface)
	return nil
}

// enableForwarding enables IP forwarding so the connector can route traffic to internal networks.
func (s *Service) enableForwarding() error {
	if runtime.GOOS != "linux" {
		s.logger.Println("IP forwarding only configured on Linux")
		return nil
	}

	cmd := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %s: %w", string(output), err)
	}

	// Add iptables FORWARD ACCEPT rules so tunnel traffic can reach local networks
	// (default FORWARD policy is often DROP; LOG alone doesn't accept)
	for _, network := range s.config.Networks {
		// Allow: tunnel (100.64.x.x) -> site network
		checkCmd := exec.Command("iptables", "-C", "FORWARD", "-s", "100.64.0.0/16", "-d", network, "-j", "ACCEPT")
		if checkCmd.Run() != nil {
			cmd := exec.Command("iptables", "-A", "FORWARD", "-s", "100.64.0.0/16", "-d", network, "-j", "ACCEPT")
			if output, err := cmd.CombinedOutput(); err != nil {
				s.logger.Printf("WARNING: iptables FORWARD ACCEPT failed (-> %s): %s", network, string(output))
			} else {
				s.logger.Printf("iptables FORWARD ACCEPT: 100.64.0.0/16 -> %s", network)
			}
		}
		// Allow: site network -> tunnel (return traffic)
		checkCmd = exec.Command("iptables", "-C", "FORWARD", "-s", network, "-d", "100.64.0.0/16", "-j", "ACCEPT")
		if checkCmd.Run() != nil {
			cmd := exec.Command("iptables", "-A", "FORWARD", "-s", network, "-d", "100.64.0.0/16", "-j", "ACCEPT")
			if output, err := cmd.CombinedOutput(); err != nil {
				s.logger.Printf("WARNING: iptables FORWARD ACCEPT failed (%s -> tunnel): %s", network, string(output))
			} else {
				s.logger.Printf("iptables FORWARD ACCEPT: %s -> 100.64.0.0/16", network)
			}
		}
	}

	// Add iptables rules for NAT/masquerade
	for _, network := range s.config.Networks {
		// Check if rule already exists before adding
		checkCmd := exec.Command("iptables", "-t", "nat", "-C", "POSTROUTING",
			"-s", "100.64.0.0/16", "-d", network, "-j", "MASQUERADE")
		if checkCmd.Run() == nil {
			s.logger.Printf("iptables NAT rule for %s already exists, skipping", network)
			continue
		}

		cmd := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING",
			"-s", "100.64.0.0/16", "-d", network, "-j", "MASQUERADE")
		if output, err := cmd.CombinedOutput(); err != nil {
			s.logger.Printf("WARNING: iptables NAT rule failed for %s: %s (error: %v)", network, string(output), err)
		} else {
			s.logger.Printf("iptables NAT rule added for %s", network)
		}

		// Add logging rules to track traffic
		// Log incoming traffic from WireGuard tunnel to internal networks
		checkCmd = exec.Command("iptables", "-C", "FORWARD",
			"-s", "100.64.0.0/16", "-d", network,
			"-j", "LOG", "--log-prefix", fmt.Sprintf("ZTNA-CONNECTOR[%s]: ", s.config.ConnectorID[:8]))
		if checkCmd.Run() == nil {
			s.logger.Printf("iptables LOG rule for %s -> %s already exists, skipping", "100.64.0.0/16", network)
		} else {
			cmd = exec.Command("iptables", "-A", "FORWARD",
				"-s", "100.64.0.0/16", "-d", network,
				"-j", "LOG", "--log-prefix", fmt.Sprintf("ZTNA-CONNECTOR[%s]: ", s.config.ConnectorID[:8]),
				"--log-level", "4")
			if output, err := cmd.CombinedOutput(); err != nil {
				s.logger.Printf("WARNING: iptables LOG rule failed for %s -> %s: %s (error: %v)", "100.64.0.0/16", network, string(output), err)
			} else {
				s.logger.Printf("iptables LOG rule added for %s -> %s", "100.64.0.0/16", network)
			}
		}

		// Log return traffic from internal networks to WireGuard tunnel
		checkCmd = exec.Command("iptables", "-C", "FORWARD",
			"-s", network, "-d", "100.64.0.0/16",
			"-j", "LOG", "--log-prefix", fmt.Sprintf("ZTNA-CONNECTOR[%s]: ", s.config.ConnectorID[:8]))
		if checkCmd.Run() == nil {
			s.logger.Printf("iptables LOG rule for %s -> %s already exists, skipping", network, "100.64.0.0/16")
		} else {
			cmd = exec.Command("iptables", "-A", "FORWARD",
				"-s", network, "-d", "100.64.0.0/16",
				"-j", "LOG", "--log-prefix", fmt.Sprintf("ZTNA-CONNECTOR[%s]: ", s.config.ConnectorID[:8]),
				"--log-level", "4")
			if output, err := cmd.CombinedOutput(); err != nil {
				s.logger.Printf("WARNING: iptables LOG rule failed for %s -> %s: %s (error: %v)", network, "100.64.0.0/16", string(output), err)
			} else {
				s.logger.Printf("iptables LOG rule added for %s -> %s", network, "100.64.0.0/16")
			}
		}
	}

	s.logger.Println("IP forwarding and NAT rules configured")
	s.logger.Println("Traffic logging enabled - check /var/log/kern.log or journalctl -k for ZTNA-CONNECTOR logs")
	return nil
}

// monitorTraffic monitors iptables logs and displays them in real-time.
func (s *Service) monitorTraffic() {
	// Try journalctl if available (systemd)
	cmd := exec.Command("journalctl", "-k", "-f", "--no-pager")
	cmd.Stderr = nil // Suppress errors if journalctl not available

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return // Can't monitor, that's OK
	}

	if err := cmd.Start(); err != nil {
		return // Can't monitor, that's OK
	}
	defer cmd.Process.Kill()

	scanner := bufio.NewScanner(stdout)
	for s.running && scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "ZTNA-CONNECTOR") {
			// Parse and format the log line
			s.logger.Printf("🔍 TRAFIC: %s", line)
		}
	}
}

// heartbeatLoop sends periodic heartbeats to the Control Plane.
func (s *Service) heartbeatLoop() {
	ticker := time.NewTicker(time.Duration(s.config.HeartbeatSec) * time.Second)
	defer ticker.Stop()

	for s.running {
		select {
		case <-ticker.C:
			s.sendHeartbeat()
		}
	}
}

// sendHeartbeat sends a heartbeat to the Control Plane.
func (s *Service) sendHeartbeat() {
	data, _ := json.Marshal(map[string]string{
		"connector_id": s.config.ConnectorID,
		"token":        s.config.Token,
	})

	url := fmt.Sprintf("%s/api/connector/heartbeat", s.config.ControlPlaneURL)
	resp, err := http.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		s.logger.Printf("Heartbeat failed: %v", err)
		return
	}
	defer resp.Body.Close()
}

// writeFile is a helper that writes content to a file.
func writeFile(path, content string) error {
	cmd := exec.Command("tee", path)
	cmd.Stdin = bytes.NewReader([]byte(content))
	return cmd.Run()
}

// getKeysPath returns the path to the saved keys file.
func (s *Service) getKeysPath() string {
	// Save in /etc/ztna/ or current directory if not writable
	paths := []string{
		"/etc/ztna/connector-keys.json",
		"./connector-keys.json",
	}
	for _, p := range paths {
		dir := filepath.Dir(p)
		if err := os.MkdirAll(dir, 0700); err == nil {
			return p
		}
	}
	return "./connector-keys.json"
}

// saveKeys saves the WireGuard keys to a file for reuse on restart.
func (s *Service) saveKeys(keyPair wireguard.KeyPair) error {
	keysPath := s.getKeysPath()
	keysData := map[string]string{
		"public_key":  keyPair.PublicKey,
		"private_key": keyPair.PrivateKey,
	}
	data, err := json.Marshal(keysData)
	if err != nil {
		return fmt.Errorf("failed to marshal keys: %w", err)
	}
	return os.WriteFile(keysPath, data, 0600)
}

// loadKeys loads saved WireGuard keys from file.
func (s *Service) loadKeys() (wireguard.KeyPair, error) {
	keysPath := s.getKeysPath()
	data, err := os.ReadFile(keysPath)
	if err != nil {
		return wireguard.KeyPair{}, fmt.Errorf("no saved keys found: %w", err)
	}
	var keysData map[string]string
	if err := json.Unmarshal(data, &keysData); err != nil {
		return wireguard.KeyPair{}, fmt.Errorf("failed to parse keys file: %w", err)
	}
	return wireguard.KeyPair{
		PublicKey:  keysData["public_key"],
		PrivateKey: keysData["private_key"],
	}, nil
}
