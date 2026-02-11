// Command agent-fyne is the ZTNA client agent with a native Fyne GUI.
// This version uses the same WireGuard logic as the web agent but with a native Windows GUI.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"image/color"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

var (
	controlPlaneDefault = "http://176.136.202.205:8080"
	logger              = log.New(os.Stdout, "[ZTNA] ", log.LstdFlags)
	connected           bool
	tunnelIP            string
	agentID             string
	connectedAt         time.Time
	wgInterface         = "wg-ztna"
)

func main() {
	controlPlane := flag.String("control-plane", controlPlaneDefault, "URL du Control Plane")
	flag.Parse()

	myApp := app.NewWithID("com.ztna.agent")

	myWindow := myApp.NewWindow("ZTNA Sovereign — Agent Client")
	myWindow.Resize(fyne.NewSize(500, 600))
	myWindow.CenterOnScreen()

	// Dark theme
	myApp.Settings().SetTheme(&darkTheme{})

	// Create UI
	content := createLoginUI(myWindow, *controlPlane)
	myWindow.SetContent(content)

	myWindow.ShowAndRun()
}

// createLoginUI creates the login interface.
func createLoginUI(window fyne.Window, controlPlane string) fyne.CanvasObject {
	emailEntry := widget.NewEntry()
	emailEntry.SetPlaceHolder("vous@entreprise.fr")

	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("••••••••••")

	controlPlaneEntry := widget.NewEntry()
	controlPlaneEntry.SetText(controlPlane)
	controlPlaneEntry.SetPlaceHolder("http://votre-serveur:8080")

	statusLabel := widget.NewLabel("")
	statusLabel.Wrapping = fyne.TextWrapWord

	connectBtn := widget.NewButton("🔐 Connexion Sécurisée", nil)
	connectBtn.OnTapped = func() {
		email := emailEntry.Text
		password := passwordEntry.Text
		cp := controlPlaneEntry.Text
		if cp == "" {
			cp = controlPlaneDefault
		}

		if email == "" || password == "" {
			statusLabel.SetText("❌ Email et mot de passe requis")
			statusLabel.Importance = widget.HighImportance
			return
		}

		connectBtn.SetText("⏳ Connexion...")
		connectBtn.Disable()
		statusLabel.SetText("🔄 Authentification en cours...")
		statusLabel.Importance = widget.MediumImportance

		go func() {
			// Update status during connection (must use fyne.Do for thread safety)
			fyne.Do(func() {
				statusLabel.SetText("🔄 Authentification...")
			})
			
			// Check if WireGuard needs installation (Windows only)
			if runtime.GOOS == "windows" && !isWireGuardInstalled() {
				fyne.Do(func() {
					statusLabel.SetText("🔧 WireGuard requis\n📥 Installation automatique...\n⚠️  Acceptez l'élévation UAC si demandé")
					statusLabel.Importance = widget.MediumImportance
				})
			}
			
			if err := connectToZTNA(email, password, cp); err != nil {
				fyne.Do(func() {
					statusLabel.SetText(fmt.Sprintf("❌ %s", err.Error()))
					statusLabel.Importance = widget.HighImportance
					connectBtn.SetText("🔐 Connexion Sécurisée")
					connectBtn.Enable()
				})
				return
			}

			// Switch to connected view (must use fyne.Do)
			fyne.Do(func() {
				window.SetContent(createConnectedUI(window, cp))
			})
		}()
	}

	form := container.NewVBox(
		widget.NewCard("", "ZTNA Sovereign", container.NewVBox(
			widget.NewLabel("🔐 Connexion Zero Trust"),
			widget.NewSeparator(),
		)),
		widget.NewForm(
			widget.NewFormItem("Email", emailEntry),
			widget.NewFormItem("Mot de passe", passwordEntry),
			widget.NewFormItem("Control Plane", controlPlaneEntry),
		),
		connectBtn,
		statusLabel,
		widget.NewSeparator(),
		widget.NewLabel("🔒 Tunnel WireGuard chiffré de bout en bout"),
	)

	return container.NewPadded(form)
}

// createConnectedUI creates the connected dashboard.
func createConnectedUI(window fyne.Window, controlPlane string) fyne.CanvasObject {
	tunnelIPLabel := widget.NewRichTextFromMarkdown(fmt.Sprintf("**IP Tunnel:** `%s`", tunnelIP))
	agentIDLabel := widget.NewRichTextFromMarkdown(fmt.Sprintf("**Agent ID:** `%s`", agentID))
	
	timerLabel := widget.NewLabel("00:00:00")
	timerLabel.Alignment = fyne.TextAlignCenter
	
	// Update timer every second (must use fyne.Do for thread safety)
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if connected {
				duration := time.Since(connectedAt)
				h := int(duration.Hours())
				m := int(duration.Minutes()) % 60
				s := int(duration.Seconds()) % 60
				fyne.Do(func() {
					timerLabel.SetText(fmt.Sprintf("%02d:%02d:%02d", h, m, s))
				})
			}
		}
	}()

	disconnectBtn := widget.NewButton("⏏ Déconnecter", func() {
		disconnectFromZTNA()
		window.SetContent(createLoginUI(window, controlPlane))
	})

	statusCard := widget.NewCard("", "✅ Connecté", container.NewVBox(
		widget.NewLabel("Statut: Tunnel actif"),
		timerLabel,
		widget.NewLabel("Durée de connexion"),
	))

	// Diagnostic button
	diagnosticBtn := widget.NewButton("🔍 Diagnostic Réseau", func() {
		showDiagnosticWindow(window, controlPlane)
	})

	infoCard := widget.NewCard("", "Informations", container.NewVBox(
		tunnelIPLabel,
		agentIDLabel,
		widget.NewLabel(fmt.Sprintf("Serveur: %s", controlPlane)),
	))

	return container.NewVBox(
		statusCard,
		infoCard,
		widget.NewSeparator(),
		diagnosticBtn,
		disconnectBtn,
	)
}

// connectToZTNA handles the connection process.
func connectToZTNA(email, password, controlPlane string) error {
	// Step 1: Login
	loginResp, err := login(email, password, controlPlane)
	if err != nil {
		return fmt.Errorf("authentification échouée: %w", err)
	}

	// Step 2: Register agent
	regResp, err := registerAgent(loginResp.Token, controlPlane)
	if err != nil {
		return fmt.Errorf("enregistrement échoué: %w", err)
	}

	tunnelIP = regResp.TunnelIP
	agentID = regResp.AgentID

	// Step 3: Apply WireGuard config (same logic as web agent)
	if regResp.ConfigINI != "" {
		// Check if WireGuard needs to be installed first (Windows only)
		if runtime.GOOS == "windows" && !isWireGuardInstalled() {
			logger.Println("WireGuard n'est pas installé. Installation automatique...")
			if err := installWireGuardAutomatically(logger); err != nil {
				return fmt.Errorf("installation WireGuard échouée: %w", err)
			}
			// Wait a moment for installation to complete
			time.Sleep(1 * time.Second)
		}
		
		if err := applyWireGuardConfig(wgInterface, regResp.ConfigINI); err != nil {
			return fmt.Errorf("tunnel WireGuard: %w", err)
		}
	}

	connected = true
	connectedAt = time.Now()
	logger.Printf("Connecté: IP=%s, AgentID=%s", tunnelIP, agentID)
	return nil
}

// disconnectFromZTNA tears down the connection.
func disconnectFromZTNA() {
	teardownWireGuard(wgInterface)
	connected = false
	logger.Println("Déconnecté")
}

// applyWireGuardConfig applies WireGuard configuration (reuses logic from cmd/agent).
func applyWireGuardConfig(iface string, configINI string) error {
	if configINI == "" {
		return fmt.Errorf("aucune configuration WireGuard reçue")
	}
	switch runtime.GOOS {
	case "linux":
		return applyWireGuardLinux(iface, configINI)
	case "windows":
		return applyWireGuardWindows(iface, configINI)
	case "darwin":
		return applyWireGuardDarwin(iface, configINI)
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

func applyWireGuardWindows(iface string, configINI string) error {
	// Check if WireGuard is installed
	wgPaths := []string{
		`C:\Program Files\WireGuard\wireguard.exe`,
		`C:\Program Files (x86)\WireGuard\wireguard.exe`,
	}
	var wgPath string
	for _, path := range wgPaths {
		if _, err := os.Stat(path); err == nil {
			wgPath = path
			break
		}
	}
	if wgPath == "" {
		// Try PATH
		if path, err := exec.LookPath("wireguard.exe"); err == nil {
			wgPath = path
		} else {
			// WireGuard not installed - try automatic installation
			logger.Println("WireGuard n'est pas installé. Tentative d'installation automatique...")
			if err := installWireGuardAutomatically(logger); err != nil {
				return fmt.Errorf("WireGuard n'est pas installé et l'installation automatique a échoué: %v. Installez-le manuellement depuis https://www.wireguard.com/install/", err)
			}
			// Retry finding WireGuard after installation
			for _, path := range wgPaths {
				if _, err := os.Stat(path); err == nil {
					wgPath = path
					break
				}
			}
			if wgPath == "" {
				if path, err := exec.LookPath("wireguard.exe"); err == nil {
					wgPath = path
				} else {
					return fmt.Errorf("WireGuard installé mais non détecté. Redémarrez l'agent.")
				}
			}
		}
	}

	configDir := `C:\ProgramData\WireGuard`
	os.MkdirAll(configDir, 0755)
	configPath := fmt.Sprintf(`%s\%s.conf`, configDir, iface)
	
	// Uninstall old tunnel first (if exists)
	logger.Println("Désinstallation de l'ancien tunnel...")
	exec.Command(wgPath, "/uninstalltunnelservice", iface).Run()
	os.Remove(configPath)
	
	if err := os.WriteFile(configPath, []byte(configINI), 0600); err != nil {
		return fmt.Errorf("impossible d'écrire la config: %w", err)
	}

	logger.Printf("Config WireGuard écrite: %s", configPath)
	logger.Printf("Contenu config (AllowedIPs): %s", extractAllowedIPs(configINI))

	// Install tunnel service (requires admin - try with elevation if needed)
	cmd := exec.Command(wgPath, "/installtunnelservice", configPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Try with elevation using PowerShell
		logger.Println("Tentative d'installation avec élévation UAC...")
		psScript := fmt.Sprintf(`Start-Process -FilePath "%s" -ArgumentList "/installtunnelservice", "%s" -Verb RunAs -Wait`, wgPath, configPath)
		cmd = exec.Command("powershell", "-Command", psScript)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		output2, err2 := cmd.CombinedOutput()
		if err2 != nil {
			return fmt.Errorf("échec installation tunnel WireGuard: %s. Lancez l'agent en tant qu'Administrateur ou acceptez l'élévation UAC", string(output))
		}
		logger.Printf("Installation réussie avec élévation: %s", string(output2))
	}

	logger.Println("Tunnel WireGuard installé avec succès")
	return nil
}

func applyWireGuardDarwin(iface string, configINI string) error {
	configPath := fmt.Sprintf("/usr/local/etc/wireguard/%s.conf", iface)
	os.MkdirAll("/usr/local/etc/wireguard", 0755)
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

func teardownWireGuard(iface string) {
	switch runtime.GOOS {
	case "windows":
		exec.Command("wireguard.exe", "/uninstalltunnelservice", iface).Run()
		configPath := fmt.Sprintf(`C:\ProgramData\WireGuard\%s.conf`, iface)
		os.Remove(configPath)
	case "linux", "darwin":
		exec.Command("wg-quick", "down", iface).Run()
	}
	logger.Println("Tunnel WireGuard fermé")
}

// login authenticates with the Control Plane.
func login(email, password, controlPlane string) (*LoginResponse, error) {
	reqBody := map[string]string{"email": email, "password": password}
	data, _ := json.Marshal(reqBody)

	resp, err := http.Post(fmt.Sprintf("%s/api/auth/login", controlPlane), "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("erreur %d: %s", resp.StatusCode, string(body))
	}

	var result LoginResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// registerAgent registers the agent.
func registerAgent(token, controlPlane string) (*RegistrationResponse, error) {
	hostname, _ := os.Hostname()
	reqBody := map[string]string{
		"token":       token,
		"device_name": hostname,
		"os":          runtime.GOOS,
	}
	data, _ := json.Marshal(reqBody)

	resp, err := http.Post(fmt.Sprintf("%s/api/agent/register", controlPlane), "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("erreur %d: %s", resp.StatusCode, string(body))
	}

	var result RegistrationResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

type LoginResponse struct {
	Token string `json:"token"`
	User  struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Name  string `json:"name"`
	} `json:"user"`
}

type RegistrationResponse struct {
	AgentID   string `json:"agent_id"`
	TunnelIP  string `json:"tunnel_ip"`
	ConfigINI string `json:"config_ini"`
}

// darkTheme provides a dark theme for the app.
type darkTheme struct{}

func (t *darkTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameBackground:
		return color.RGBA{10, 14, 26, 255} // #0a0e1a
	case theme.ColorNameButton:
		return color.RGBA{56, 189, 248, 255} // #38bdf8 (blue)
	case theme.ColorNameForeground:
		return color.RGBA{226, 232, 240, 255} // #e2e8f0
	case theme.ColorNameInputBackground:
		return color.RGBA{15, 23, 42, 255} // #0f172a
	case theme.ColorNameInputBorder:
		return color.RGBA{56, 189, 248, 51} // rgba(56,189,248,0.2)
	default:
		return theme.DefaultTheme().Color(name, variant)
	}
}

func (t *darkTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(style)
}

func (t *darkTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

func (t *darkTheme) Size(name fyne.ThemeSizeName) float32 {
	return theme.DefaultTheme().Size(name)
}

// extractAllowedIPs extracts AllowedIPs from WireGuard config for logging.
func extractAllowedIPs(configINI string) string {
	lines := strings.Split(configINI, "\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "AllowedIPs") {
			return strings.TrimSpace(line)
		}
	}
	return "non trouvé"
}

// showDiagnosticWindow shows a diagnostic window for network troubleshooting.
func showDiagnosticWindow(parent fyne.Window, controlPlane string) {
	diagWindow := fyne.CurrentApp().NewWindow("🔍 Diagnostic Réseau")
	diagWindow.Resize(fyne.NewSize(600, 500))
	diagWindow.CenterOnScreen()

	resultsText := widget.NewRichText()
	resultsText.Wrapping = fyne.TextWrapWord
	scroll := container.NewScroll(resultsText)
	scroll.SetMinSize(fyne.NewSize(580, 400))

	testIPEntry := widget.NewEntry()
	testIPEntry.SetPlaceHolder("192.168.75.130")
	testIPEntry.SetText("192.168.75.130")

	runDiagnosticBtn := widget.NewButton("▶️ Lancer Diagnostic", nil)
	runDiagnosticBtn.OnTapped = func() {
		testIP := testIPEntry.Text
		if testIP == "" {
			testIP = "192.168.75.130"
		}

		runDiagnosticBtn.SetText("⏳ Diagnostic...")
		runDiagnosticBtn.Disable()

		go func() {
			results := runNetworkDiagnostic(testIP, controlPlane)
			fyne.Do(func() {
				resultsText.ParseMarkdown(results)
				runDiagnosticBtn.SetText("▶️ Lancer Diagnostic")
				runDiagnosticBtn.Enable()
			})
		}()
	}

	content := container.NewVBox(
		widget.NewCard("", "Test de Connectivité", container.NewVBox(
			widget.NewForm(
				widget.NewFormItem("IP à tester", testIPEntry),
			),
			runDiagnosticBtn,
		)),
		widget.NewSeparator(),
		widget.NewLabel("Résultats :"),
		scroll,
	)

	diagWindow.SetContent(container.NewPadded(content))
	diagWindow.Show()
}

// runNetworkDiagnostic runs network diagnostic tests.
func runNetworkDiagnostic(testIP, controlPlane string) string {
	var results strings.Builder
	results.WriteString("# 🔍 Diagnostic Réseau\n\n")

	// 1. Check WireGuard config
	results.WriteString("## 1. Configuration WireGuard\n\n")
	configPath := fmt.Sprintf(`C:\ProgramData\WireGuard\%s.conf`, wgInterface)
	configData, err := os.ReadFile(configPath)
	if err != nil {
		results.WriteString(fmt.Sprintf("❌ Config non trouvée: %s\n\n", err))
	} else {
		configINI := string(configData)
		allowedIPs := extractAllowedIPs(configINI)
		results.WriteString(fmt.Sprintf("✅ Config trouvée: %s\n", configPath))
		results.WriteString(fmt.Sprintf("📋 %s\n\n", allowedIPs))
		
		// Check if testIP network is in AllowedIPs
		if strings.Contains(allowedIPs, "192.168.75") {
			results.WriteString("✅ Réseau 192.168.75.0/24 présent dans AllowedIPs\n\n")
		} else {
			results.WriteString("❌ Réseau 192.168.75.0/24 NON présent dans AllowedIPs\n\n")
		}
	}

	// 2. Check routes
	results.WriteString("## 2. Routes Système\n\n")
	cmd := exec.Command("route", "print")
	output, err := cmd.CombinedOutput()
	if err != nil {
		results.WriteString(fmt.Sprintf("❌ Erreur route print: %s\n\n", err))
	} else {
		routeOutput := string(output)
		if strings.Contains(routeOutput, "192.168.75") {
			results.WriteString("✅ Route vers 192.168.75.0/24 trouvée\n\n")
		} else {
			results.WriteString("❌ Route vers 192.168.75.0/24 NON trouvée\n\n")
		}
	}

	// 3. Ping test
	results.WriteString("## 3. Test de Connectivité\n\n")
	results.WriteString(fmt.Sprintf("Test vers %s...\n\n", testIP))
	
	pingCmd := exec.Command("ping", "-n", "4", testIP)
	pingOutput, err := pingCmd.CombinedOutput()
	if err != nil {
		results.WriteString(fmt.Sprintf("❌ Ping échoué: %s\n\n", err))
	} else {
		pingResult := string(pingOutput)
		if strings.Contains(pingResult, "TTL=") || strings.Contains(pingResult, "TTL expiré") {
			results.WriteString("✅ Ping réussi (paquets reçus)\n\n")
		} else {
			results.WriteString("❌ Ping timeout (aucune réponse)\n\n")
		}
		results.WriteString(fmt.Sprintf("```\n%s\n```\n\n", pingResult))
	}

	// 4. Traceroute
	results.WriteString("## 4. Traceroute\n\n")
	tracertCmd := exec.Command("tracert", "-h", "10", testIP)
	tracertOutput, err := tracertCmd.CombinedOutput()
	if err != nil {
		results.WriteString(fmt.Sprintf("⚠️ Traceroute échoué: %s\n\n", err))
	} else {
		results.WriteString(fmt.Sprintf("```\n%s\n```\n\n", string(tracertOutput)))
	}

	// 5. WireGuard interface
	results.WriteString("## 5. Interface WireGuard\n\n")
	wgCmd := exec.Command("ipconfig")
	wgOutput, err := wgCmd.CombinedOutput()
	if err == nil {
		wgResult := string(wgOutput)
		if strings.Contains(wgResult, "100.64") {
			results.WriteString("✅ Interface WireGuard active (IP 100.64.x.x)\n\n")
		} else {
			results.WriteString("❌ Interface WireGuard non trouvée\n\n")
		}
	}

	results.WriteString("## 📝 Recommandations\n\n")
	results.WriteString("1. Vérifie que le connecteur est en ligne dans le dashboard\n")
	results.WriteString("2. Vérifie que la politique autorise bien 192.168.75.0/24\n")
	results.WriteString("3. Vérifie que le PoP a le forwarding IP activé\n")
	results.WriteString("4. Vérifie que le connecteur a le forwarding IP et les règles iptables\n")

	return results.String()
}
