// Command api starts the ZTNA Sovereign Control Plane API server.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ztna-sovereign/ztna/internal/api"
	"github.com/ztna-sovereign/ztna/internal/auth"
	"github.com/ztna-sovereign/ztna/internal/models"
	"github.com/ztna-sovereign/ztna/internal/policy"
	"github.com/ztna-sovereign/ztna/internal/tunnel"
	"github.com/ztna-sovereign/ztna/internal/wireguard"
)

func main() {
	// Flags
	host := flag.String("host", "0.0.0.0", "Server host")
	port := flag.Int("port", 8080, "Server port")
	dbHost := flag.String("db-host", "", "PostgreSQL host (vide = mode memoire)")
	dbPort := flag.Int("db-port", 5432, "PostgreSQL port")
	dbUser := flag.String("db-user", "ztna", "PostgreSQL user")
	dbPass := flag.String("db-pass", "ztna-secret", "PostgreSQL password")
	dbName := flag.String("db-name", "ztna_sovereign", "PostgreSQL database name")
	dbSSL := flag.String("db-ssl", "disable", "PostgreSQL SSL mode")
	jwtSecret := flag.String("jwt-secret", "ztna-sovereign-secret-change-in-prod", "JWT signing secret")
	tokenDuration := flag.Duration("token-duration", 24*time.Hour, "JWT token duration")
	userCIDR := flag.String("user-cidr", "100.64.0.0/16", "CIDR for user tunnel IPs (plage CGNAT, evite conflits LAN)")
	connCIDR := flag.String("connector-cidr", "100.65.0.0/16", "CIDR for connector tunnel IPs")
	flag.Parse()

	logger := log.New(os.Stdout, "[ZTNA] ", log.LstdFlags|log.Lshortfile)

	logger.Println("==============================================")
	logger.Println("  ZTNA Sovereign - Control Plane")
	logger.Println("  Solution ZTNA souveraine francaise")
	logger.Println("==============================================")

	// Data Store
	var store models.DataStore

	if *dbHost != "" {
		// PostgreSQL mode
		logger.Printf("Connexion a PostgreSQL %s:%d...", *dbHost, *dbPort)
		db, err := models.NewDB(models.DBConfig{
			Host:     *dbHost,
			Port:     *dbPort,
			User:     *dbUser,
			Password: *dbPass,
			DBName:   *dbName,
			SSLMode:  *dbSSL,
		})
		if err != nil {
			logger.Fatalf("Connexion PostgreSQL echouee: %v", err)
		}
		logger.Println("PostgreSQL connecte")

		if err := db.Migrate(context.Background()); err != nil {
			logger.Fatalf("Migration echouee: %v", err)
		}
		logger.Println("Migrations appliquees")
		store = db
	} else {
		// In-memory mode
		logger.Println("Mode memoire (pas de PostgreSQL)")
		logger.Println("Les donnees seront perdues au redemarrage.")
		logger.Println("Pour persister: --db-host=localhost")
		store = models.NewMemStore()
	}

	// JWT Manager
	jwtMgr := auth.NewJWTManager(*jwtSecret, *tokenDuration)

	// Policy Engine
	policyEngine := policy.NewEngine(store)
	policyEngine.LoadPolicies(context.Background())

	// Tunnel Manager
	tunnelMgr := tunnel.NewManager()

	// WireGuard Config Generator
	configGen, err := wireguard.NewConfigGenerator(*userCIDR, *connCIDR)
	if err != nil {
		logger.Fatalf("Erreur init WireGuard config: %v", err)
	}

	// OIDC Provider (optional)
	var oidcProvider *auth.OIDCProvider
	oidcIssuer := os.Getenv("OIDC_ISSUER")
	if oidcIssuer != "" {
		oidcProvider, err = auth.NewOIDCProvider(auth.OIDCConfig{
			Issuer:       oidcIssuer,
			ClientID:     os.Getenv("OIDC_CLIENT_ID"),
			ClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),
			RedirectURL:  os.Getenv("OIDC_REDIRECT_URL"),
		})
		if err != nil {
			logger.Printf("Warning: OIDC echoue: %v", err)
		} else {
			logger.Printf("OIDC configure: %s", oidcIssuer)
		}
	}

	// API Server
	server := api.NewServer(store, jwtMgr, oidcProvider, policyEngine, tunnelMgr, configGen, logger)
	handler := server.SetupRoutes()

	addr := fmt.Sprintf("%s:%d", *host, *port)
	httpServer := &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		logger.Println("Arret en cours...")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		httpServer.Shutdown(ctx)
	}()

	logger.Printf("API en ecoute sur %s", addr)
	logger.Printf("Dashboard: http://localhost:%d", *port)
	logger.Printf("API Health: http://localhost:%d/api/health", *port)
	logger.Println("")
	logger.Println("Premier lancement ? Ouvrez le dashboard pour creer le compte admin.")

	if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
		logger.Fatalf("Erreur serveur: %v", err)
	}

	logger.Println("Serveur arrete")
}
