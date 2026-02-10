// +build !windows

package main

import (
	"fmt"
	"log"
	"os/exec"
	"runtime"
)

// installWireGuardAutomatically is a stub for non-Windows platforms.
func installWireGuardAutomatically(logger *log.Logger) error {
	return fmt.Errorf("installation automatique non disponible sur %s. Installez WireGuard manuellement", runtime.GOOS)
}

// isWireGuardInstalled checks if WireGuard is installed (stub for non-Windows).
func isWireGuardInstalled() bool {
	// On Linux/Mac, check for wg-quick in PATH
	if _, err := exec.LookPath("wg-quick"); err == nil {
		return true
	}
	return false
}
