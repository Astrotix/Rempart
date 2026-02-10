// Package wireguard handles WireGuard key generation, configuration creation,
// and interface management for the ZTNA platform.
package wireguard

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"sync"

	"golang.org/x/crypto/curve25519"

	"github.com/ztna-sovereign/ztna/internal/models"
)

// KeyPair holds a WireGuard key pair.
type KeyPair struct {
	PrivateKey string
	PublicKey  string
}

// GenerateKeyPair generates a new WireGuard Curve25519 key pair.
func GenerateKeyPair() (*KeyPair, error) {
	// Generate 32 random bytes for private key
	var privateKey [32]byte
	if _, err := rand.Read(privateKey[:]); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Clamp the private key per Curve25519 spec
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	// Derive public key
	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	return &KeyPair{
		PrivateKey: base64.StdEncoding.EncodeToString(privateKey[:]),
		PublicKey:  base64.StdEncoding.EncodeToString(publicKey[:]),
	}, nil
}

// GeneratePresharedKey generates a random preshared key for additional security.
func GeneratePresharedKey() (string, error) {
	var psk [32]byte
	if _, err := rand.Read(psk[:]); err != nil {
		return "", fmt.Errorf("failed to generate preshared key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(psk[:]), nil
}

// IPAllocator manages allocation of WireGuard tunnel IPs from a CIDR range.
type IPAllocator struct {
	mu        sync.Mutex
	network   *net.IPNet
	allocated map[string]bool
	nextIP    net.IP
}

// NewIPAllocator creates a new IP allocator for the given CIDR range.
// Example: "10.100.0.0/16" for user tunnels.
func NewIPAllocator(cidr string) (*IPAllocator, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %s: %w", cidr, err)
	}

	// Start from first usable IP (skip network address)
	startIP := make(net.IP, len(network.IP))
	copy(startIP, network.IP)
	incrementIP(startIP)

	return &IPAllocator{
		network:   network,
		allocated: make(map[string]bool),
		nextIP:    startIP,
	}, nil
}

// Allocate assigns the next available IP address.
func (a *IPAllocator) Allocate() (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	for {
		ip := a.nextIP.String()
		incrementIP(a.nextIP)

		// Check we're still in the network
		if !a.network.Contains(a.nextIP) {
			return "", fmt.Errorf("IP pool exhausted for network %s", a.network.String())
		}

		// Skip if already allocated
		if a.allocated[ip] {
			continue
		}

		a.allocated[ip] = true
		// Return with /32 mask for point-to-point
		ones, _ := a.network.Mask.Size()
		return fmt.Sprintf("%s/%d", ip, ones), nil
	}
}

// Release frees an allocated IP address back to the pool.
func (a *IPAllocator) Release(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Strip mask if present
	cleanIP := strings.Split(ip, "/")[0]
	delete(a.allocated, cleanIP)
}

// MarkAllocated marks an IP as already in use (for loading state from DB).
func (a *IPAllocator) MarkAllocated(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	cleanIP := strings.Split(ip, "/")[0]
	a.allocated[cleanIP] = true
}

// incrementIP increments an IP address by 1.
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// ConfigGenerator generates WireGuard configuration files.
type ConfigGenerator struct {
	UserNetwork      string // CIDR for user tunnel IPs, e.g. "100.64.0.0/16"
	ConnectorNetwork string // CIDR for site connector tunnel IPs, e.g. "100.65.0.0/16"
	userAllocator    *IPAllocator
	connAllocator    *IPAllocator
}

// NewConfigGenerator creates a new configuration generator.
func NewConfigGenerator(userCIDR, connectorCIDR string) (*ConfigGenerator, error) {
	userAlloc, err := NewIPAllocator(userCIDR)
	if err != nil {
		return nil, fmt.Errorf("user IP allocator: %w", err)
	}

	connAlloc, err := NewIPAllocator(connectorCIDR)
	if err != nil {
		return nil, fmt.Errorf("connector IP allocator: %w", err)
	}

	return &ConfigGenerator{
		UserNetwork:      userCIDR,
		ConnectorNetwork: connectorCIDR,
		userAllocator:    userAlloc,
		connAllocator:    connAlloc,
	}, nil
}

// GeneratePoPConfig generates the WireGuard configuration for a PoP server.
func (cg *ConfigGenerator) GeneratePoPConfig(pop *models.PoP, userPeers []models.WireGuardPeer, sitePeers []models.WireGuardPeer) *models.WireGuardConfig {
	allPeers := make([]models.WireGuardPeer, 0, len(userPeers)+len(sitePeers))
	allPeers = append(allPeers, userPeers...)
	allPeers = append(allPeers, sitePeers...)

	return &models.WireGuardConfig{
		PrivateKey: pop.PrivateKey,
		Address:    fmt.Sprintf("%s/24", pop.PublicIP), // PoP uses its own subnet
		ListenPort: pop.WGPort,
		Peers:      allPeers,
	}
}

// GenerateClientConfig generates a WireGuard config for a client agent.
func (cg *ConfigGenerator) GenerateClientConfig(agent *models.ClientAgent, pop *models.PoP, psk string) *models.WireGuardConfig {
	return &models.WireGuardConfig{
		PrivateKey: agent.PrivateKey,
		Address:    agent.AssignedIP,
		DNS:        []string{"1.1.1.1", "9.9.9.9"}, // Can be customized
		Peers: []models.WireGuardPeer{
			{
				PublicKey:    pop.PublicKey,
				AllowedIPs:   []string{"0.0.0.0/0"}, // Route all traffic through tunnel
				Endpoint:     fmt.Sprintf("%s:%d", pop.PublicIP, pop.WGPort),
				PresharedKey: psk,
				KeepAlive:    25,
			},
		},
	}
}

// GenerateConnectorConfig generates a WireGuard config for a site connector.
func (cg *ConfigGenerator) GenerateConnectorConfig(connector *models.SiteConnector, pop *models.PoP, tunnelIP string, psk string) *models.WireGuardConfig {
	return &models.WireGuardConfig{
		PrivateKey: connector.PrivateKey,
		Address:    tunnelIP,
		Peers: []models.WireGuardPeer{
			{
				PublicKey:    pop.PublicKey,
				AllowedIPs:   []string{"100.64.0.0/16", "100.65.0.0/16"}, // Allow traffic from user and connector tunnel networks
				Endpoint:     fmt.Sprintf("%s:%d", pop.PublicIP, pop.WGPort),
				PresharedKey: psk,
				KeepAlive:    25, // Keep NAT mappings alive (essential for outbound-only tunnel)
			},
		},
	}
}

// AllocateUserIP allocates a new tunnel IP for a user agent.
func (cg *ConfigGenerator) AllocateUserIP() (string, error) {
	return cg.userAllocator.Allocate()
}

// AllocateConnectorIP allocates a new tunnel IP for a site connector.
func (cg *ConfigGenerator) AllocateConnectorIP() (string, error) {
	return cg.connAllocator.Allocate()
}

// RenderINI renders a WireGuard config to INI format (wg-quick compatible).
func RenderINI(config *models.WireGuardConfig) string {
	var sb strings.Builder

	sb.WriteString("[Interface]\n")
	sb.WriteString(fmt.Sprintf("PrivateKey = %s\n", config.PrivateKey))
	sb.WriteString(fmt.Sprintf("Address = %s\n", config.Address))

	if config.ListenPort > 0 {
		sb.WriteString(fmt.Sprintf("ListenPort = %d\n", config.ListenPort))
	}

	if len(config.DNS) > 0 {
		sb.WriteString(fmt.Sprintf("DNS = %s\n", strings.Join(config.DNS, ", ")))
	}

	for _, peer := range config.Peers {
		sb.WriteString("\n[Peer]\n")
		sb.WriteString(fmt.Sprintf("PublicKey = %s\n", peer.PublicKey))

		if peer.PresharedKey != "" {
			sb.WriteString(fmt.Sprintf("PresharedKey = %s\n", peer.PresharedKey))
		}

		if len(peer.AllowedIPs) > 0 {
			sb.WriteString(fmt.Sprintf("AllowedIPs = %s\n", strings.Join(peer.AllowedIPs, ", ")))
		}

		if peer.Endpoint != "" {
			sb.WriteString(fmt.Sprintf("Endpoint = %s\n", peer.Endpoint))
		}

		if peer.KeepAlive > 0 {
			sb.WriteString(fmt.Sprintf("PersistentKeepalive = %d\n", peer.KeepAlive))
		}
	}

	return sb.String()
}
