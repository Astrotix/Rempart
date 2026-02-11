// +build windows

package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// installWireGuardAutomatically downloads and installs WireGuard automatically.
func installWireGuardAutomatically(logger *log.Logger) error {
	logger.Println("🔧 Installation automatique de WireGuard...")

	// Check if already installed
	if isWireGuardInstalled() {
		logger.Println("✅ WireGuard est déjà installé")
		return nil
	}

	// Download WireGuard installer
	installerURL := "https://download.wireguard.com/windows-client/wireguard-installer.exe"
	installerPath := filepath.Join(os.TempDir(), "wireguard-installer.exe")

	logger.Printf("📥 Téléchargement de WireGuard depuis %s...", installerURL)
	resp, err := http.Get(installerURL)
	if err != nil {
		return fmt.Errorf("impossible de télécharger WireGuard: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("erreur HTTP %d lors du téléchargement", resp.StatusCode)
	}

	file, err := os.Create(installerPath)
	if err != nil {
		return fmt.Errorf("impossible de créer le fichier: %w", err)
	}
	defer file.Close()

	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return fmt.Errorf("erreur lors de l'écriture: %w", err)
	}
	file.Close()

	logger.Printf("✅ Téléchargement terminé: %s", installerPath)
	logger.Println("🔧 Lancement de l'installateur WireGuard avec élévation...")
	logger.Println("   ⚠️  Une fenêtre UAC va s'ouvrir. Acceptez l'élévation pour continuer.")

	// Use PowerShell to run installer with elevation (RunAs)
	// This will automatically prompt for UAC
	psScript := fmt.Sprintf(`Start-Process -FilePath "%s" -ArgumentList "/S" -Verb RunAs -Wait`, installerPath)
	cmd := exec.Command("powershell", "-Command", psScript)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		// Cleanup on error
		os.Remove(installerPath)
		return fmt.Errorf("erreur lors de l'installation: %w (avez-vous accepté l'élévation UAC ?)", err)
	}

	// Wait a bit for installation to complete
	time.Sleep(2 * time.Second)

	// Verify installation
	if !isWireGuardInstalled() {
		os.Remove(installerPath)
		return fmt.Errorf("WireGuard installé mais non détecté. Redémarrez l'agent.")
	}

	// Cleanup
	os.Remove(installerPath)

	logger.Println("✅ WireGuard installé avec succès !")
	logger.Println("   🔄 Redémarrez l'agent pour utiliser le tunnel WireGuard.")

	return nil
}

// isWireGuardInstalled checks if WireGuard is already installed.
func isWireGuardInstalled() bool {
	paths := []string{
		`C:\Program Files\WireGuard\wireguard.exe`,
		`C:\Program Files (x86)\WireGuard\wireguard.exe`,
	}
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	// Also check PATH
	if _, err := exec.LookPath("wireguard.exe"); err == nil {
		return true
	}
	return false
}
