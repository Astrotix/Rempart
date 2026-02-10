// Package policy implements the Zero Trust policy engine that determines
// whether a user is allowed to access a specific resource through the ZTNA.
package policy

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/ztna-sovereign/ztna/internal/models"
)

// Engine is the Zero Trust policy evaluation engine.
type Engine struct {
	mu       sync.RWMutex
	policies []models.Policy
	db       PolicyStore
}

// PolicyStore is the interface for loading policies from storage.
type PolicyStore interface {
	ListPolicies(ctx context.Context) ([]models.Policy, error)
}

// AccessRequest represents a request to access a resource.
type AccessRequest struct {
	UserID      string
	GroupIDs    []string
	ConnectorID string
	DestIP      string
	DestPort    int
}

// AccessDecision is the result of a policy evaluation.
type AccessDecision struct {
	Allowed  bool
	PolicyID string
	Reason   string
}

// NewEngine creates a new policy engine.
func NewEngine(db PolicyStore) *Engine {
	return &Engine{
		db: db,
	}
}

// LoadPolicies loads all policies from the database into memory for fast evaluation.
func (e *Engine) LoadPolicies(ctx context.Context) error {
	policies, err := e.db.ListPolicies(ctx)
	if err != nil {
		return fmt.Errorf("failed to load policies: %w", err)
	}

	e.mu.Lock()
	e.policies = policies
	e.mu.Unlock()

	return nil
}

// Evaluate checks whether an access request is allowed based on loaded policies.
// Policies are evaluated in priority order (lowest number = highest priority).
// The first matching policy determines the outcome.
// If no policy matches, access is DENIED by default (Zero Trust).
func (e *Engine) Evaluate(req *AccessRequest) *AccessDecision {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, policy := range e.policies {
		if !policy.Enabled {
			continue
		}

		// Check if the policy matches the request
		if !e.matchesSource(policy, req) {
			continue
		}

		if !e.matchesDestination(policy, req) {
			continue
		}

		// Policy matches
		allowed := policy.Action == models.PolicyActionAllow
		return &AccessDecision{
			Allowed:  allowed,
			PolicyID: policy.ID,
			Reason:   fmt.Sprintf("matched policy '%s' (priority %d, action %s)", policy.Name, policy.Priority, policy.Action),
		}
	}

	// Default deny - Zero Trust principle
	return &AccessDecision{
		Allowed:  false,
		PolicyID: "",
		Reason:   "no matching policy found - default deny (Zero Trust)",
	}
}

// matchesSource checks if the policy source (user or group) matches the request.
func (e *Engine) matchesSource(policy models.Policy, req *AccessRequest) bool {
	switch policy.SourceType {
	case models.SourceTypeUser:
		return policy.SourceID == req.UserID
	case models.SourceTypeGroup:
		for _, gid := range req.GroupIDs {
			if gid == policy.SourceID {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// matchesDestination checks if the policy destination matches the request.
func (e *Engine) matchesDestination(policy models.Policy, req *AccessRequest) bool {
	// Check connector ID
	if policy.DestConnectorID != req.ConnectorID {
		return false
	}

	// Check network (if specified)
	if len(policy.DestNetworks) > 0 && req.DestIP != "" {
		networkMatch := false
		reqIP := net.ParseIP(req.DestIP)
		if reqIP == nil {
			return false
		}

		for _, cidr := range policy.DestNetworks {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			if network.Contains(reqIP) {
				networkMatch = true
				break
			}
		}
		if !networkMatch {
			return false
		}
	}

	// Check port (if specified)
	if len(policy.DestPorts) > 0 && req.DestPort > 0 {
		portMatch := false
		reqPortStr := strconv.Itoa(req.DestPort)

		for _, portSpec := range policy.DestPorts {
			if portSpec == "*" {
				portMatch = true
				break
			}

			// Handle port ranges like "8000-9000"
			if strings.Contains(portSpec, "-") {
				parts := strings.SplitN(portSpec, "-", 2)
				low, err1 := strconv.Atoi(parts[0])
				high, err2 := strconv.Atoi(parts[1])
				if err1 == nil && err2 == nil && req.DestPort >= low && req.DestPort <= high {
					portMatch = true
					break
				}
			}

			if portSpec == reqPortStr {
				portMatch = true
				break
			}
		}
		if !portMatch {
			return false
		}
	}

	return true
}

// GetPoliciesForUser returns all policies that apply to a specific user (directly or via groups).
func (e *Engine) GetPoliciesForUser(userID string, groupIDs []string) []models.Policy {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var result []models.Policy
	for _, policy := range e.policies {
		if !policy.Enabled {
			continue
		}
		if policy.SourceType == models.SourceTypeUser && policy.SourceID == userID {
			result = append(result, policy)
			continue
		}
		if policy.SourceType == models.SourceTypeGroup {
			for _, gid := range groupIDs {
				if gid == policy.SourceID {
					result = append(result, policy)
					break
				}
			}
		}
	}
	return result
}

// GetAllowedConnectors returns the list of connector IDs a user is allowed to access.
func (e *Engine) GetAllowedConnectors(userID string, groupIDs []string) []string {
	policies := e.GetPoliciesForUser(userID, groupIDs)
	connectorSet := make(map[string]bool)
	for _, p := range policies {
		if p.Action == models.PolicyActionAllow {
			connectorSet[p.DestConnectorID] = true
		}
	}
	var result []string
	for c := range connectorSet {
		result = append(result, c)
	}
	return result
}
