// Command pop starts the ZTNA PoP (Point of Presence) service.
// This runs on each PoP server (OVHcloud instances in Gravelines, Strasbourg, Roubaix).
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	popService "github.com/ztna-sovereign/ztna/internal/pop"
)

func main() {
	popID := flag.String("pop-id", "", "Unique PoP identifier")
	controlPlane := flag.String("control-plane", "http://localhost:8080", "Control Plane URL")
	wgInterface := flag.String("wg-interface", "wg0", "WireGuard interface name")
	wgPort := flag.Int("wg-port", 51820, "WireGuard listen port")
	heartbeat := flag.Int("heartbeat", 30, "Heartbeat interval in seconds")
	apiPort := flag.Int("api-port", 8081, "Local API port for PoP management")
	flag.Parse()

	if *popID == "" {
		hostname, _ := os.Hostname()
		*popID = fmt.Sprintf("pop-%s", hostname)
	}

	logger := log.New(os.Stdout, fmt.Sprintf("[PoP:%s] ", *popID), log.LstdFlags|log.Lshortfile)

	logger.Println("==============================================")
	logger.Println("  ZTNA Sovereign - PoP Service")
	logger.Printf("  PoP ID: %s", *popID)
	logger.Printf("  Control Plane: %s", *controlPlane)
	logger.Printf("  WireGuard: %s (port %d)", *wgInterface, *wgPort)
	logger.Println("==============================================")

	svc, err := popService.NewService(popService.Config{
		PoPID:           *popID,
		ControlPlaneURL: *controlPlane,
		WGInterface:     *wgInterface,
		WGPort:          *wgPort,
		HeartbeatSec:    *heartbeat,
	}, logger)
	if err != nil {
		logger.Fatalf("Failed to create PoP service: %v", err)
	}

	if err := svc.Start(); err != nil {
		logger.Fatalf("Failed to start PoP service: %v", err)
	}

	// Local management API
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","pop_id":"%s"}`, *popID)
	})

	go func() {
		addr := fmt.Sprintf("127.0.0.1:%d", *apiPort)
		logger.Printf("Local management API on %s", addr)
		if err := http.ListenAndServe(addr, mux); err != nil {
			logger.Printf("Local API error: %v", err)
		}
	}()

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	svc.Stop()
	logger.Println("PoP service stopped")
}
