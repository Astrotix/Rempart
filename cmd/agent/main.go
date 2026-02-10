// Command agent is the ZTNA client agent that runs on the user's device.
// It authenticates via OIDC, receives a WireGuard config, and establishes
// a tunnel to the nearest PoP.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/ztna-sovereign/ztna/internal/wireguard"
)

// AgentConfig holds the client agent configuration.
type AgentConfig struct {
	ControlPlaneURL string `json:"control_plane_url"`
	Token           string `json:"token"`      // JWT token from OIDC login
	DeviceName      string `json:"device_name"`
	WGInterface     string `json:"wg_interface"`
}

// RegistrationResponse is the response from the Control Plane after registration.
type RegistrationResponse struct {
	AgentID   string `json:"agent_id"`
	TunnelIP  string `json:"tunnel_ip"`
	ConfigINI string `json:"config_ini"`
}

func main() {
	controlPlane := flag.String("control-plane", "http://localhost:8080", "Control Plane URL")
	token := flag.String("token", "", "JWT auth token (from OIDC login)")
	deviceName := flag.String("device", "", "Device name")
	wgInterface := flag.String("wg-interface", "wg-ztna", "WireGuard interface name")
	flag.Parse()

	if *token == "" {
		fmt.Println("Usage: ztna-agent --token <JWT_TOKEN> --control-plane <URL>")
		fmt.Println()
		fmt.Println("Get your token by logging in at: <control-plane-url>/api/auth/login")
		os.Exit(1)
	}

	if *deviceName == "" {
		hostname, _ := os.Hostname()
		*deviceName = hostname
	}

	logger := log.New(os.Stdout, "[Agent] ", log.LstdFlags|log.Lshortfile)

	logger.Println("==============================================")
	logger.Println("  ZTNA Sovereign - Client Agent")
	logger.Printf("  Device: %s (%s)", *deviceName, runtime.GOOS)
	logger.Printf("  Control Plane: %s", *controlPlane)
	logger.Println("==============================================")

	config := AgentConfig{
		ControlPlaneURL: *controlPlane,
		Token:           *token,
		DeviceName:      *deviceName,
		WGInterface:     *wgInterface,
	}

	// Step 1: Register with Control Plane
	logger.Println("Registering with Control Plane...")
	regResp, err := registerAgent(config)
	if err != nil {
		logger.Fatalf("Registration failed: %v", err)
	}

	logger.Printf("Registered! Agent ID: %s, Tunnel IP: %s", regResp.AgentID, regResp.TunnelIP)

	// Step 2: Apply WireGuard configuration
	logger.Println("Configuring WireGuard tunnel...")
	if err := applyWireGuardConfig(config.WGInterface, regResp.ConfigINI, logger); err != nil {
		logger.Printf("WARNING: WireGuard setup failed: %v", err)
		logger.Println("Config that should be applied manually:")
		logger.Println(regResp.ConfigINI)
	} else {
		logger.Println("WireGuard tunnel established!")
	}

	// Step 3: Keep alive and monitor
	logger.Println("Connected to ZTNA network. Press Ctrl+C to disconnect.")

	go monitorConnection(config, logger)

	// Wait for shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	// Cleanup
	logger.Println("Disconnecting...")
	teardownWireGuard(config.WGInterface, logger)
	logger.Println("Disconnected from ZTNA network")
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
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("registration failed with status %d", resp.StatusCode)
	}

	var result RegistrationResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// applyWireGuardConfig applies the WireGuard configuration on the local system.
func applyWireGuardConfig(iface string, configINI string, logger *log.Logger) error {
	switch runtime.GOOS {
	case "linux":
		return applyWireGuardLinux(iface, configINI)
	case "windows":
		return applyWireGuardWindows(iface, configINI, logger)
	case "darwin":
		return applyWireGuardDarwin(iface, configINI, logger)
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

func applyWireGuardLinux(iface string, configINI string) error {
	configPath := fmt.Sprintf("/etc/wireguard/%s.conf", iface)
	if err := os.WriteFile(configPath, []byte(configINI), 0600); err != nil {
		return err
	}
	cmd := exec.Command("wg-quick", "up", iface)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("wg-quick up failed: %s: %w", string(output), err)
	}
	return nil
}

func applyWireGuardWindows(iface string, configINI string, logger *log.Logger) error {
	// On Windows, use the WireGuard tunnel service
	configPath := fmt.Sprintf(`C:\ProgramData\WireGuard\%s.conf`, iface)
	if err := os.MkdirAll(`C:\ProgramData\WireGuard`, 0755); err != nil {
		logger.Printf("Could not create WireGuard config dir: %v", err)
	}
	if err := os.WriteFile(configPath, []byte(configINI), 0600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	// Try to use wireguard.exe CLI
	cmd := exec.Command("wireguard.exe", "/installtunnelservice", configPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		logger.Printf("WireGuard service install failed: %s", string(output))
		return fmt.Errorf("wireguard.exe not found or failed. Install WireGuard for Windows")
	}
	return nil
}

func applyWireGuardDarwin(iface string, configINI string, logger *log.Logger) error {
	// On macOS, use wg-quick via Homebrew
	configPath := fmt.Sprintf("/usr/local/etc/wireguard/%s.conf", iface)
	_ = os.MkdirAll("/usr/local/etc/wireguard", 0755)
	if err := os.WriteFile(configPath, []byte(configINI), 0600); err != nil {
		return err
	}
	cmd := exec.Command("wg-quick", "up", iface)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("wg-quick up failed: %s: %w", string(output), err)
	}
	return nil
}

// teardownWireGuard removes the WireGuard tunnel.
func teardownWireGuard(iface string, logger *log.Logger) {
	switch runtime.GOOS {
	case "linux", "darwin":
		exec.Command("wg-quick", "down", iface).Run()
	case "windows":
		configPath := fmt.Sprintf(`C:\ProgramData\WireGuard\%s.conf`, iface)
		exec.Command("wireguard.exe", "/uninstalltunnelservice", iface).Run()
		os.Remove(configPath)
	}
	logger.Println("WireGuard tunnel torn down")
}

// monitorConnection periodically checks tunnel health.
func monitorConnection(config AgentConfig, logger *log.Logger) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	_ = wireguard.RenderINI // Keep import alive

	for range ticker.C {
		// Check if WireGuard interface is up
		if runtime.GOOS == "linux" {
			cmd := exec.Command("wg", "show", config.WGInterface)
			if err := cmd.Run(); err != nil {
				logger.Println("WARNING: WireGuard tunnel appears down, attempting reconnect...")
				// In production: implement reconnection logic
			}
		}
	}
}
