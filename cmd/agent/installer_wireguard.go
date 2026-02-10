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
	logger.Println("🔧 Lancement de l'installateur WireGuard...")
	logger.Println("   ⚠️  Une fenêtre d'installation va s'ouvrir. Suivez les instructions.")
	logger.Println("   ⚠️  Vous devrez peut-être accepter l'élévation de privilèges (UAC).")

	// Run installer (silent mode)
	cmd := exec.Command(installerPath, "/S")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("erreur lors de l'installation: %w", err)
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
