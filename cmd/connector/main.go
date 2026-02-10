// Command connector starts the ZTNA Site Connector service.
// This runs on the client's internal network (VM, Raspberry Pi, Docker container)
// and creates an outbound WireGuard tunnel to the nearest PoP.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	connectorService "github.com/ztna-sovereign/ztna/internal/connector"
)

func main() {
	controlPlane := flag.String("control-plane", "http://localhost:8080", "Control Plane URL")
	token := flag.String("token", "", "Activation token (from Control Plane dashboard)")
	wgInterface := flag.String("wg-interface", "wg-connector", "WireGuard interface name")
	networks := flag.String("networks", "", "Comma-separated internal networks to expose (ex: 10.0.0.0/24,172.16.0.0/24)")
	heartbeat := flag.Int("heartbeat", 30, "Heartbeat interval in seconds")
	flag.Parse()

	if *token == "" {
		fmt.Println("Usage: ztna-connector --token <ACTIVATION_TOKEN> --control-plane <URL>")
		fmt.Println()
		fmt.Println("The activation token is generated when you create a new site connector")
		fmt.Println("in the ZTNA Sovereign dashboard.")
		os.Exit(1)
	}

	logger := log.New(os.Stdout, "[Connector] ", log.LstdFlags|log.Lshortfile)

	logger.Println("==============================================")
	logger.Println("  ZTNA Sovereign - Site Connector")
	logger.Printf("  Control Plane: %s", *controlPlane)
	logger.Printf("  Networks: %s", *networks)
	logger.Println("==============================================")

	// Parse networks
	netList := parseNetworks(*networks)

	svc := connectorService.NewService(connectorService.Config{
		ControlPlaneURL: *controlPlane,
		Token:           *token,
		WGInterface:     *wgInterface,
		Networks:        netList,
		HeartbeatSec:    *heartbeat,
	}, logger)

	if err := svc.Start(); err != nil {
		logger.Fatalf("Failed to start connector: %v", err)
	}

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	svc.Stop()
	logger.Println("Site connector stopped")
}

func parseNetworks(s string) []string {
	var result []string
	for _, n := range splitAndTrim(s) {
		if n != "" {
			result = append(result, n)
		}
	}
	return result
}

func splitAndTrim(s string) []string {
	var result []string
	current := ""
	for _, c := range s {
		if c == ',' {
			result = append(result, trim(current))
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		result = append(result, trim(current))
	}
	return result
}

func trim(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}
