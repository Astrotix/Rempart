// Package auth provides OIDC authentication, JWT token management,
// and middleware for the ZTNA platform.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/ztna-sovereign/ztna/internal/models"
)

// OIDCConfig holds the OIDC provider configuration.
type OIDCConfig struct {
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectURL  string `json:"redirect_url"`
	Scopes       []string `json:"scopes"`
}

// OIDCProvider handles OIDC authentication flows.
type OIDCProvider struct {
	Config       OIDCConfig
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
	JWKSUrl      string
}

// OIDCDiscovery represents the OIDC discovery document.
type OIDCDiscovery struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserInfoEndpoint      string   `json:"userinfo_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	ScopesSupported       []string `json:"scopes_supported"`
}

// NewOIDCProvider creates a new OIDC provider by discovering endpoints.
func NewOIDCProvider(cfg OIDCConfig) (*OIDCProvider, error) {
	discoveryURL := strings.TrimRight(cfg.Issuer, "/") + "/.well-known/openid-configuration"

	resp, err := http.Get(discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OIDC discovery: %w", err)
	}
	defer resp.Body.Close()

	var discovery OIDCDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return nil, fmt.Errorf("failed to parse OIDC discovery: %w", err)
	}

	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "email", "profile"}
	}

	return &OIDCProvider{
		Config:      cfg,
		AuthURL:     discovery.AuthorizationEndpoint,
		TokenURL:    discovery.TokenEndpoint,
		UserInfoURL: discovery.UserInfoEndpoint,
		JWKSUrl:     discovery.JWKSURI,
	}, nil
}

// GenerateState generates a cryptographic random state parameter for OIDC flow.
func GenerateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// GetAuthURL returns the OIDC authorization URL for user login.
func (p *OIDCProvider) GetAuthURL(state string) string {
	params := fmt.Sprintf(
		"?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&state=%s",
		p.Config.ClientID,
		p.Config.RedirectURL,
		strings.Join(p.Config.Scopes, "+"),
		state,
	)
	return p.AuthURL + params
}

// OIDCTokenResponse represents the token response from the OIDC provider.
type OIDCTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

// OIDCUserInfo represents the userinfo response from the OIDC provider.
type OIDCUserInfo struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

// ExchangeCode exchanges an authorization code for tokens.
func (p *OIDCProvider) ExchangeCode(ctx context.Context, code string) (*OIDCTokenResponse, error) {
	body := fmt.Sprintf(
		"grant_type=authorization_code&code=%s&redirect_uri=%s&client_id=%s&client_secret=%s",
		code, p.Config.RedirectURL, p.Config.ClientID, p.Config.ClientSecret,
	)

	req, err := http.NewRequestWithContext(ctx, "POST", p.TokenURL, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}
	defer resp.Body.Close()

	var tokenResp OIDCTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	return &tokenResp, nil
}

// GetUserInfo fetches user info from the OIDC provider.
func (p *OIDCProvider) GetUserInfo(ctx context.Context, accessToken string) (*OIDCUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", p.UserInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("userinfo request failed: %w", err)
	}
	defer resp.Body.Close()

	var userInfo OIDCUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to parse userinfo: %w", err)
	}

	return &userInfo, nil
}

// --- JWT Token Management ---

// JWTManager handles creation and validation of internal JWT tokens.
type JWTManager struct {
	SecretKey     []byte
	TokenDuration time.Duration
}

// ZTNAClaims are the custom JWT claims for the ZTNA platform.
type ZTNAClaims struct {
	jwt.RegisteredClaims
	UserID string         `json:"user_id"`
	Email  string         `json:"email"`
	Role   models.UserRole `json:"role"`
}

// NewJWTManager creates a new JWT manager.
func NewJWTManager(secret string, duration time.Duration) *JWTManager {
	return &JWTManager{
		SecretKey:     []byte(secret),
		TokenDuration: duration,
	}
}

// GenerateToken creates a new JWT token for a user.
func (m *JWTManager) GenerateToken(user *models.User) (string, error) {
	claims := ZTNAClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.ID,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(m.TokenDuration)),
			Issuer:    "ztna-sovereign",
		},
		UserID: user.ID,
		Email:  user.Email,
		Role:   user.Role,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.SecretKey)
}

// ValidateToken validates a JWT token and returns the claims.
func (m *JWTManager) ValidateToken(tokenString string) (*ZTNAClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &ZTNAClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return m.SecretKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*ZTNAClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}

// --- HTTP Middleware ---

// contextKey is a custom type for context keys.
type contextKey string

const userClaimsKey contextKey = "user_claims"

// AuthMiddleware creates an HTTP middleware that validates JWT tokens.
func (m *JWTManager) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, `{"error": "missing authorization header"}`, http.StatusUnauthorized)
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			http.Error(w, `{"error": "invalid authorization format"}`, http.StatusUnauthorized)
			return
		}

		claims, err := m.ValidateToken(parts[1])
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error": "%s"}`, err.Error()), http.StatusUnauthorized)
			return
		}

		// Add claims to context
		ctx := context.WithValue(r.Context(), userClaimsKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AdminMiddleware restricts access to admin users only.
func AdminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := GetClaimsFromContext(r.Context())
		if claims == nil || claims.Role != models.RoleAdmin {
			http.Error(w, `{"error": "admin access required"}`, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// GetClaimsFromContext extracts JWT claims from the request context.
func GetClaimsFromContext(ctx context.Context) *ZTNAClaims {
	claims, ok := ctx.Value(userClaimsKey).(*ZTNAClaims)
	if !ok {
		return nil
	}
	return claims
}
