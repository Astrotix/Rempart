// Package api provides the HTTP REST API handlers for the ZTNA Control Plane.
package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/ztna-sovereign/ztna/internal/auth"
	"github.com/ztna-sovereign/ztna/internal/models"
	"github.com/ztna-sovereign/ztna/internal/policy"
	"github.com/ztna-sovereign/ztna/internal/tunnel"
	"github.com/ztna-sovereign/ztna/internal/wireguard"
)

// Server holds all dependencies for the API server.
type Server struct {
	Store         models.DataStore
	JWTManager    *auth.JWTManager
	OIDCProvider  *auth.OIDCProvider
	PolicyEngine  *policy.Engine
	TunnelManager *tunnel.Manager
	ConfigGen     *wireguard.ConfigGenerator
	Logger        *log.Logger
}

// NewServer creates a new API server with all dependencies.
func NewServer(store models.DataStore, jwtMgr *auth.JWTManager, oidc *auth.OIDCProvider, pe *policy.Engine, tm *tunnel.Manager, cg *wireguard.ConfigGenerator, logger *log.Logger) *Server {
	return &Server{
		Store:         store,
		JWTManager:    jwtMgr,
		OIDCProvider:  oidc,
		PolicyEngine:  pe,
		TunnelManager: tm,
		ConfigGen:     cg,
		Logger:        logger,
	}
}

// SetupRoutes configures all API routes.
func (s *Server) SetupRoutes() http.Handler {
	mux := http.NewServeMux()

	// Public routes (no auth required)
	mux.HandleFunc("GET /api/health", s.handleHealth)
	mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	mux.HandleFunc("GET /api/auth/login", s.handleOIDCLogin)
	mux.HandleFunc("GET /api/auth/callback", s.handleOIDCCallback)
	mux.HandleFunc("POST /api/auth/setup", s.handleSetup)
	mux.HandleFunc("GET /api/auth/check", s.handleAuthCheck)

	// Agent/Connector registration (token-based auth)
	mux.HandleFunc("POST /api/agent/register", s.handleAgentRegister)
	mux.HandleFunc("POST /api/connector/register", s.handleConnectorRegister)
	mux.HandleFunc("POST /api/connector/heartbeat", s.handleConnectorHeartbeat)
	mux.HandleFunc("POST /api/pop/heartbeat", s.handlePoPHeartbeat)

	// Protected routes (JWT required)
	protected := http.NewServeMux()
	protected.HandleFunc("GET /api/users", s.handleListUsers)
	protected.HandleFunc("POST /api/users", s.handleCreateUser)
	protected.HandleFunc("GET /api/users/{id}", s.handleGetUser)
	protected.HandleFunc("PUT /api/users/{id}", s.handleUpdateUser)
	protected.HandleFunc("DELETE /api/users/{id}", s.handleDeleteUser)

	protected.HandleFunc("GET /api/pops", s.handleListPoPs)
	protected.HandleFunc("POST /api/pops", s.handleCreatePoP)
	protected.HandleFunc("GET /api/pops/{id}", s.handleGetPoP)

	protected.HandleFunc("GET /api/connectors", s.handleListConnectors)
	protected.HandleFunc("POST /api/connectors", s.handleCreateConnector)
	protected.HandleFunc("GET /api/connectors/{id}/config", s.handleGetConnectorConfig)

	protected.HandleFunc("GET /api/policies", s.handleListPolicies)
	protected.HandleFunc("POST /api/policies", s.handleCreatePolicy)
	protected.HandleFunc("DELETE /api/policies/{id}", s.handleDeletePolicy)

	protected.HandleFunc("GET /api/audit-logs", s.handleListAuditLogs)
	protected.HandleFunc("GET /api/stats", s.handleGetStats)

	protected.HandleFunc("GET /api/agent/config", s.handleGetAgentConfig)

	// Connector {id} routes - register in main mux BEFORE mounting sub-mux to avoid pattern matching conflicts
	// Handle both GET and DELETE for /api/connectors/{id}
	connectorIDHandler := s.JWTManager.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" {
			s.handleDeleteConnector(w, r)
		} else if r.Method == "GET" {
			s.handleGetConnector(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}))
	mux.Handle("/api/connectors/{id}", connectorIDHandler)

	// Apply auth middleware to protected routes
	mux.Handle("/api/", s.JWTManager.AuthMiddleware(protected))

	// Apply CORS middleware to everything
	return corsMiddleware(mux)
}

// --- Health ---

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	stats := s.TunnelManager.GetStats()
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":  "ok",
		"version": "0.1.0",
		"stats":   stats,
	})
}

// --- Auth ---

// hashPassword creates a SHA-256 hash of a password (use bcrypt in production).
func hashPassword(password string) string {
	h := sha256.Sum256([]byte(password))
	return hex.EncodeToString(h[:])
}

// handleSetup creates the first admin user. Only works if no users exist.
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Corps de requete invalide")
		return
	}

	if req.Email == "" || req.Password == "" {
		jsonError(w, http.StatusBadRequest, "Email et mot de passe requis")
		return
	}

	// Check if any user already exists
	users, _ := s.Store.ListUsers(r.Context())
	if len(users) > 0 {
		jsonError(w, http.StatusConflict, "Le setup a deja ete effectue. Utilisez /api/auth/login.")
		return
	}

	user := &models.User{
		Email:   req.Email,
		Name:    req.Name,
		Role:    models.RoleAdmin,
		OIDCSub: hashPassword(req.Password), // Store hashed password in OIDCSub field
	}

	if err := s.Store.CreateUser(r.Context(), user); err != nil {
		jsonError(w, http.StatusInternalServerError, "Erreur creation utilisateur: "+err.Error())
		return
	}

	token, err := s.JWTManager.GenerateToken(user)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Erreur generation token")
		return
	}

	s.Logger.Printf("Setup initial: admin %s cree", user.Email)

	// Log the event
	s.Store.CreateAuditLog(r.Context(), &models.AuditLog{
		UserID:    user.ID,
		UserEmail: user.Email,
		Action:    "setup",
		Result:    "allowed",
	})

	jsonResponse(w, http.StatusCreated, map[string]interface{}{
		"token": token,
		"user":  user,
	})
}

// handleAuthCheck checks if setup has been done (any user exists).
func (s *Server) handleAuthCheck(w http.ResponseWriter, r *http.Request) {
	users, _ := s.Store.ListUsers(r.Context())
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"setup_done":  len(users) > 0,
		"total_users": len(users),
	})
}

// handleLogin authenticates a user with email/password.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Corps de requete invalide")
		return
	}

	user, err := s.Store.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		jsonError(w, http.StatusUnauthorized, "Email ou mot de passe incorrect")
		return
	}

	if user.Disabled {
		jsonError(w, http.StatusForbidden, "Compte desactive")
		return
	}

	// Verify password
	if user.OIDCSub != hashPassword(req.Password) {
		jsonError(w, http.StatusUnauthorized, "Email ou mot de passe incorrect")
		return
	}

	token, err := s.JWTManager.GenerateToken(user)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Erreur generation token")
		return
	}

	s.Logger.Printf("Login: %s (%s)", user.Email, user.Role)

	s.Store.CreateAuditLog(r.Context(), &models.AuditLog{
		UserID:    user.ID,
		UserEmail: user.Email,
		Action:    "login",
		Result:    "allowed",
		ClientIP:  r.RemoteAddr,
	})

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"token": token,
		"user":  user,
	})
}

func (s *Server) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	if s.OIDCProvider == nil {
		jsonResponse(w, http.StatusOK, map[string]string{
			"message": "OIDC non configure. Utilisez /api/auth/login avec email/password.",
		})
		return
	}

	state, err := auth.GenerateState()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Erreur generation state")
		return
	}

	url := s.OIDCProvider.GetAuthURL(state)
	http.Redirect(w, r, url, http.StatusFound)
}

func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if s.OIDCProvider == nil {
		jsonError(w, http.StatusBadRequest, "OIDC non configure")
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		jsonError(w, http.StatusBadRequest, "Code d'autorisation manquant")
		return
	}

	tokenResp, err := s.OIDCProvider.ExchangeCode(r.Context(), code)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Echange de token echoue: "+err.Error())
		return
	}

	userInfo, err := s.OIDCProvider.GetUserInfo(r.Context(), tokenResp.AccessToken)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Impossible de recuperer les infos utilisateur: "+err.Error())
		return
	}

	user, err := s.Store.GetUserByOIDCSub(r.Context(), userInfo.Sub)
	if err != nil {
		user = &models.User{
			Email:   userInfo.Email,
			Name:    userInfo.Name,
			Role:    models.RoleUser,
			OIDCSub: userInfo.Sub,
		}
		if err := s.Store.CreateUser(r.Context(), user); err != nil {
			jsonError(w, http.StatusInternalServerError, "Erreur creation utilisateur")
			return
		}
	}

	token, err := s.JWTManager.GenerateToken(user)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Erreur generation token")
		return
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"token": token,
		"user":  user,
	})
}

// --- Users ---

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.Store.ListUsers(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Erreur listing utilisateurs")
		return
	}
	if users == nil {
		users = []models.User{}
	}
	jsonResponse(w, http.StatusOK, users)
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Name     string `json:"name"`
		Role     string `json:"role"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Corps de requete invalide")
		return
	}

	if req.Email == "" {
		jsonError(w, http.StatusBadRequest, "Email requis")
		return
	}

	role := models.UserRole(req.Role)
	if role == "" {
		role = models.RoleUser
	}

	password := req.Password
	if password == "" {
		password = req.Email // Default password = email, user should change it
	}

	user := &models.User{
		Email:   req.Email,
		Name:    req.Name,
		Role:    role,
		OIDCSub: hashPassword(password),
	}

	if err := s.Store.CreateUser(r.Context(), &*user); err != nil {
		jsonError(w, http.StatusInternalServerError, "Erreur creation utilisateur: "+err.Error())
		return
	}

	s.Logger.Printf("Utilisateur cree: %s (%s) role=%s", user.Email, user.ID, user.Role)

	s.Store.CreateAuditLog(r.Context(), &models.AuditLog{
		UserID:    user.ID,
		UserEmail: user.Email,
		Action:    "user_created",
		Result:    "allowed",
	})

	jsonResponse(w, http.StatusCreated, user)
}

func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	user, err := s.Store.GetUser(r.Context(), id)
	if err != nil {
		jsonError(w, http.StatusNotFound, "Utilisateur non trouve")
		return
	}
	jsonResponse(w, http.StatusOK, user)
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var user models.User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		jsonError(w, http.StatusBadRequest, "Corps de requete invalide")
		return
	}
	user.ID = id

	if err := s.Store.UpdateUser(r.Context(), &user); err != nil {
		jsonError(w, http.StatusInternalServerError, "Erreur mise a jour utilisateur")
		return
	}

	jsonResponse(w, http.StatusOK, user)
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	// Get user info for audit log
	user, _ := s.Store.GetUser(r.Context(), id)

	if err := s.Store.DeleteUser(r.Context(), id); err != nil {
		jsonError(w, http.StatusInternalServerError, "Erreur suppression utilisateur")
		return
	}

	if user != nil {
		s.Logger.Printf("Utilisateur supprime: %s (%s)", user.Email, id)
		s.Store.CreateAuditLog(r.Context(), &models.AuditLog{
			UserID:    id,
			UserEmail: user.Email,
			Action:    "user_deleted",
			Result:    "allowed",
		})
	}

	jsonResponse(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// --- PoPs ---

func (s *Server) handleListPoPs(w http.ResponseWriter, r *http.Request) {
	pops, err := s.Store.ListPoPs(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Erreur listing PoPs")
		return
	}
	if pops == nil {
		pops = []models.PoP{}
	}
	jsonResponse(w, http.StatusOK, pops)
}

func (s *Server) handleCreatePoP(w http.ResponseWriter, r *http.Request) {
	var pop models.PoP
	if err := json.NewDecoder(r.Body).Decode(&pop); err != nil {
		jsonError(w, http.StatusBadRequest, "Corps de requete invalide")
		return
	}

	if pop.Name == "" || pop.Location == "" || pop.PublicIP == "" {
		jsonError(w, http.StatusBadRequest, "Nom, localisation et IP publique requis")
		return
	}

	// Generate WireGuard keys for the PoP
	keyPair, err := wireguard.GenerateKeyPair()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Erreur generation cles WireGuard")
		return
	}
	pop.PublicKey = keyPair.PublicKey
	pop.PrivateKey = keyPair.PrivateKey
	pop.Status = models.PoPStatusOffline

	if pop.WGPort == 0 {
		pop.WGPort = 51820
	}
	if pop.Provider == "" {
		pop.Provider = "OVHcloud"
	}

	if err := s.Store.CreatePoP(r.Context(), &pop); err != nil {
		jsonError(w, http.StatusInternalServerError, "Erreur creation PoP: "+err.Error())
		return
	}

	s.Logger.Printf("PoP cree: %s (%s) - %s", pop.Name, pop.ID, pop.Location)

	s.Store.CreateAuditLog(r.Context(), &models.AuditLog{
		Action: "pop_created",
		PoPID:  pop.ID,
		Result: "allowed",
	})

	// Don't expose private key in response
	pop.PrivateKey = ""
	jsonResponse(w, http.StatusCreated, pop)
}

func (s *Server) handleGetPoP(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	pop, err := s.Store.GetPoP(r.Context(), id)
	if err != nil {
		jsonError(w, http.StatusNotFound, "PoP non trouve")
		return
	}
	pop.PrivateKey = ""
	jsonResponse(w, http.StatusOK, pop)
}

func (s *Server) handlePoPHeartbeat(w http.ResponseWriter, r *http.Request) {
	var metrics models.PoPMetrics
	if err := json.NewDecoder(r.Body).Decode(&metrics); err != nil {
		jsonError(w, http.StatusBadRequest, "Corps de requete invalide")
		return
	}

	if err := s.Store.UpdatePoPStatus(r.Context(), metrics.PoPID, models.PoPStatusOnline); err != nil {
		jsonError(w, http.StatusInternalServerError, "Erreur mise a jour statut PoP")
		return
	}

	jsonResponse(w, http.StatusOK, map[string]string{"status": "ok"})
}

// --- Site Connectors ---

func (s *Server) handleListConnectors(w http.ResponseWriter, r *http.Request) {
	connectors, err := s.Store.ListSiteConnectors(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Erreur listing connecteurs")
		return
	}
	if connectors == nil {
		connectors = []models.SiteConnector{}
	}
	jsonResponse(w, http.StatusOK, connectors)
}

func (s *Server) handleCreateConnector(w http.ResponseWriter, r *http.Request) {
	var conn models.SiteConnector
	if err := json.NewDecoder(r.Body).Decode(&conn); err != nil {
		jsonError(w, http.StatusBadRequest, "Corps de requete invalide")
		return
	}

	if conn.Name == "" || conn.SiteName == "" {
		jsonError(w, http.StatusBadRequest, "Nom et nom de site requis")
		return
	}

	// Generate activation token (unique, cryptographic, 32 bytes)
	token, err := auth.GenerateState()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Erreur generation token")
		return
	}
	conn.Token = token
	conn.TokenUsed = false
	conn.TokenExpiry = time.Now().Add(24 * time.Hour) // Expire dans 24h
	conn.Status = models.ConnectorStatusRegistering

	if err := s.Store.CreateSiteConnector(r.Context(), &conn); err != nil {
		jsonError(w, http.StatusInternalServerError, "Erreur creation connecteur: "+err.Error())
		return
	}

	s.Logger.Printf("Connecteur cree: %s (%s) pour site %s", conn.Name, conn.ID, conn.SiteName)

	s.Store.CreateAuditLog(r.Context(), &models.AuditLog{
		Action:      "connector_created",
		ConnectorID: conn.ID,
		Result:      "allowed",
	})

	jsonResponse(w, http.StatusCreated, conn)
}

func (s *Server) handleGetConnector(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	conn, err := s.Store.GetSiteConnector(r.Context(), id)
	if err != nil {
		jsonError(w, http.StatusNotFound, "Connecteur non trouve")
		return
	}
	jsonResponse(w, http.StatusOK, conn)
}

func (s *Server) handleGetConnectorConfig(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	conn, err := s.Store.GetSiteConnector(r.Context(), id)
	if err != nil {
		jsonError(w, http.StatusNotFound, "Connecteur non trouve")
		return
	}

	pop, err := s.Store.GetPoP(r.Context(), conn.AssignedPoPID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "PoP assigne non trouve")
		return
	}

	tunnelIP, err := s.ConfigGen.AllocateConnectorIP()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Erreur allocation IP tunnel")
		return
	}

	psk, _ := wireguard.GeneratePresharedKey()
	config := s.ConfigGen.GenerateConnectorConfig(conn, pop, tunnelIP, psk)

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(wireguard.RenderINI(config)))
}

func (s *Server) handleDeleteConnector(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.Store.DeleteSiteConnector(r.Context(), id); err != nil {
		jsonError(w, http.StatusNotFound, "Connecteur non trouve")
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{"message": "Connecteur supprime"})
}

func (s *Server) handleConnectorRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token     string `json:"token"`
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Corps de requete invalide")
		return
	}

	conn, err := s.Store.GetSiteConnectorByToken(r.Context(), req.Token)
	if err != nil {
		jsonError(w, http.StatusUnauthorized, "Token d'activation invalide")
		return
	}

	// Verify token is not already used
	if conn.TokenUsed {
		s.Logger.Printf("SECURITE: tentative reutilisation token connecteur %s (%s)", conn.Name, conn.ID)
		jsonError(w, http.StatusForbidden, "Token deja utilise. Generez un nouveau connecteur.")
		return
	}

	// Verify token is not expired
	if time.Now().After(conn.TokenExpiry) {
		s.Logger.Printf("SECURITE: token expire pour connecteur %s (%s)", conn.Name, conn.ID)
		jsonError(w, http.StatusForbidden, "Token expire. Creez un nouveau connecteur depuis le dashboard.")
		return
	}

	keyPair, err := wireguard.GenerateKeyPair()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Erreur generation cles")
		return
	}

	if err := s.Store.ActivateSiteConnector(r.Context(), conn.ID, keyPair.PublicKey, keyPair.PrivateKey); err != nil {
		jsonError(w, http.StatusInternalServerError, "Erreur activation connecteur")
		return
	}

	// Mark token as consumed (single-use)
	s.Store.MarkTokenUsed(r.Context(), conn.ID)

	pop, err := s.Store.GetPoP(r.Context(), conn.AssignedPoPID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "PoP assigne non trouve")
		return
	}

	tunnelIP, _ := s.ConfigGen.AllocateConnectorIP()
	psk, _ := wireguard.GeneratePresharedKey()
	config := s.ConfigGen.GenerateConnectorConfig(conn, pop, tunnelIP, psk)

	s.Logger.Printf("Connecteur enregistre: %s (%s)", conn.Name, conn.ID)
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"connector_id": conn.ID,
		"config":       config,
		"config_ini":   wireguard.RenderINI(config),
	})
}

func (s *Server) handleConnectorHeartbeat(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ConnectorID string `json:"connector_id"`
		Token       string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Corps de requete invalide")
		return
	}

	if err := s.Store.UpdateSiteConnectorStatus(r.Context(), req.ConnectorID, models.ConnectorStatusOnline); err != nil {
		jsonError(w, http.StatusInternalServerError, "Erreur mise a jour statut connecteur")
		return
	}

	jsonResponse(w, http.StatusOK, map[string]string{"status": "ok"})
}

// --- Policies ---

func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := s.Store.ListPolicies(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Erreur listing politiques")
		return
	}
	if policies == nil {
		policies = []models.Policy{}
	}
	jsonResponse(w, http.StatusOK, policies)
}

func (s *Server) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	var pol models.Policy
	if err := json.NewDecoder(r.Body).Decode(&pol); err != nil {
		jsonError(w, http.StatusBadRequest, "Corps de requete invalide")
		return
	}

	if pol.Name == "" {
		jsonError(w, http.StatusBadRequest, "Nom de politique requis")
		return
	}

	if err := s.Store.CreatePolicy(r.Context(), &pol); err != nil {
		jsonError(w, http.StatusInternalServerError, "Erreur creation politique: "+err.Error())
		return
	}

	s.PolicyEngine.LoadPolicies(r.Context())

	s.Logger.Printf("Politique creee: %s (%s)", pol.Name, pol.ID)

	s.Store.CreateAuditLog(r.Context(), &models.AuditLog{
		Action:   "policy_created",
		PolicyID: pol.ID,
		Result:   "allowed",
	})

	jsonResponse(w, http.StatusCreated, pol)
}

func (s *Server) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.Store.DeletePolicy(r.Context(), id); err != nil {
		jsonError(w, http.StatusInternalServerError, "Erreur suppression politique")
		return
	}

	s.PolicyEngine.LoadPolicies(r.Context())

	s.Store.CreateAuditLog(r.Context(), &models.AuditLog{
		Action:   "policy_deleted",
		PolicyID: id,
		Result:   "allowed",
	})

	jsonResponse(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// --- Agent ---

func (s *Server) handleAgentRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token      string `json:"token"`
		DeviceName string `json:"device_name"`
		OS         string `json:"os"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Corps de requete invalide")
		return
	}

	claims, err := s.JWTManager.ValidateToken(req.Token)
	if err != nil {
		jsonError(w, http.StatusUnauthorized, "Token invalide")
		return
	}

	keyPair, err := wireguard.GenerateKeyPair()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Erreur generation cles")
		return
	}

	tunnelIP, err := s.ConfigGen.AllocateUserIP()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Erreur allocation IP tunnel")
		return
	}

	agent := &models.ClientAgent{
		UserID:     claims.UserID,
		DeviceName: req.DeviceName,
		OS:         req.OS,
		PublicKey:  keyPair.PublicKey,
		PrivateKey: keyPair.PrivateKey,
		AssignedIP: tunnelIP,
	}

	if err := s.Store.CreateClientAgent(r.Context(), agent); err != nil {
		jsonError(w, http.StatusInternalServerError, "Erreur enregistrement agent")
		return
	}

	pops, _ := s.Store.ListPoPs(r.Context())
	var bestPoP *models.PoP
	for i := range pops {
		if pops[i].Status == models.PoPStatusOnline {
			bestPoP = &pops[i]
			break
		}
	}
	if bestPoP == nil && len(pops) > 0 {
		bestPoP = &pops[0]
	}

	var configINI string
	if bestPoP != nil {
		psk, _ := wireguard.GeneratePresharedKey()
		config := s.ConfigGen.GenerateClientConfig(agent, bestPoP, psk)
		configINI = wireguard.RenderINI(config)
	}

	s.Logger.Printf("Agent enregistre: %s pour user %s", agent.DeviceName, claims.Email)
	jsonResponse(w, http.StatusCreated, map[string]interface{}{
		"agent_id":   agent.ID,
		"tunnel_ip":  agent.AssignedIP,
		"config_ini": configINI,
	})
}

func (s *Server) handleGetAgentConfig(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaimsFromContext(r.Context())
	if claims == nil {
		jsonError(w, http.StatusUnauthorized, "Non autorise")
		return
	}

	agents, err := s.Store.GetClientAgentsByUser(r.Context(), claims.UserID)
	if err != nil || len(agents) == 0 {
		jsonError(w, http.StatusNotFound, "Aucun agent enregistre")
		return
	}

	jsonResponse(w, http.StatusOK, agents)
}

// --- Audit Logs ---

func (s *Server) handleListAuditLogs(w http.ResponseWriter, r *http.Request) {
	logs, err := s.Store.ListAuditLogs(r.Context(), 100)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Erreur listing logs")
		return
	}
	if logs == nil {
		logs = []models.AuditLog{}
	}
	jsonResponse(w, http.StatusOK, logs)
}

// --- Stats ---

func (s *Server) handleGetStats(w http.ResponseWriter, r *http.Request) {
	stats := s.TunnelManager.GetStats()

	pops, _ := s.Store.ListPoPs(r.Context())
	connectors, _ := s.Store.ListSiteConnectors(r.Context())
	users, _ := s.Store.ListUsers(r.Context())

	onlinePoPs := 0
	for _, p := range pops {
		if p.Status == models.PoPStatusOnline {
			onlinePoPs++
		}
	}
	onlineConnectors := 0
	for _, c := range connectors {
		if c.Status == models.ConnectorStatusOnline {
			onlineConnectors++
		}
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"tunnel_stats":      stats,
		"total_users":       len(users),
		"total_pops":        len(pops),
		"online_pops":       onlinePoPs,
		"total_connectors":  len(connectors),
		"online_connectors": onlineConnectors,
	})
}

// --- Helpers ---

func jsonResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, status int, message string) {
	jsonResponse(w, status, map[string]string{"error": message})
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}
