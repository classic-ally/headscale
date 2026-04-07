package db

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/juanfont/headscale/hscontrol/types"
	"gorm.io/gorm"
)

var (
	ErrDomainNotFound    = errors.New("domain not found")
	ErrDomainExists      = errors.New("domain already exists")
	ErrZoneHasChildren   = errors.New("zone has child domains: remove them first")
	ErrDomainNotVerified = errors.New("domain not verified")
)

func generateVerifyToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating verify token: %w", err)
	}
	return "hs-verify=" + hex.EncodeToString(b), nil
}

// findParentZone walks up domain labels to find a zone with credentials.
// For "bw.bentley.sh" it checks "bentley.sh", then "sh".
func findParentZone(tx *gorm.DB, domain string) (*types.Domain, error) {
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		candidate := strings.Join(parts[i:], ".")
		var zone types.Domain
		err := tx.Where("domain = ? AND provider IS NOT NULL AND provider != ''", candidate).First(&zone).Error
		if err == nil {
			return &zone, nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("looking up zone %s: %w", candidate, err)
		}
	}
	return nil, nil
}

func (hsdb *HSDatabase) CreateDomain(domain types.Domain) (*types.Domain, error) {
	return Write(hsdb.DB, func(tx *gorm.DB) (*types.Domain, error) {
		return CreateDomain(tx, domain)
	})
}

// CreateDomain creates a new domain entry. If a domain with the same name
// exists and has provider credentials, it upserts the credentials (zone update).
func CreateDomain(tx *gorm.DB, domain types.Domain) (*types.Domain, error) {
	var existing types.Domain
	err := tx.Where("domain = ?", domain.Domain).First(&existing).Error

	if err == nil {
		// Domain exists — upsert if this is a zone credential update
		if domain.Provider != nil && *domain.Provider != "" {
			existing.Provider = domain.Provider
			existing.APIToken = domain.APIToken
			if err := tx.Save(&existing).Error; err != nil {
				return nil, fmt.Errorf("updating zone credentials: %w", err)
			}
			return &existing, nil
		}
		return nil, ErrDomainExists
	}

	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("checking existing domain: %w", err)
	}

	// Generate verify token for new domains
	if domain.VerifyToken == nil {
		token, err := generateVerifyToken()
		if err != nil {
			return nil, err
		}
		domain.VerifyToken = &token
	}

	if err := tx.Create(&domain).Error; err != nil {
		return nil, fmt.Errorf("creating domain: %w", err)
	}

	return &domain, nil
}

func (hsdb *HSDatabase) GetDomainByName(name string) (*types.Domain, error) {
	return Read(hsdb.DB, func(tx *gorm.DB) (*types.Domain, error) {
		return GetDomainByName(tx, name)
	})
}

func GetDomainByName(tx *gorm.DB, name string) (*types.Domain, error) {
	var domain types.Domain
	if err := tx.Where("domain = ?", name).First(&domain).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrDomainNotFound
		}
		return nil, fmt.Errorf("getting domain: %w", err)
	}
	return &domain, nil
}

func (hsdb *HSDatabase) ListDomains(nodeID *types.NodeID, userID *uint) ([]types.Domain, error) {
	return Read(hsdb.DB, func(tx *gorm.DB) ([]types.Domain, error) {
		return ListDomains(tx, nodeID, userID)
	})
}

// ListDomains returns domains, optionally filtered by node and/or user.
// User filtering joins through domain_access.
func ListDomains(tx *gorm.DB, nodeID *types.NodeID, userID *uint) ([]types.Domain, error) {
	query := tx

	if nodeID != nil {
		query = query.Where("node_id = ?", *nodeID)
	}

	if userID != nil {
		query = query.Where(
			"id IN (SELECT domain_id FROM domain_access WHERE user_id = ?)",
			*userID,
		)
	}

	var domains []types.Domain
	if err := query.Find(&domains).Error; err != nil {
		return nil, fmt.Errorf("listing domains: %w", err)
	}
	return domains, nil
}

func (hsdb *HSDatabase) ListVerifiedDomainsForNode(nodeID types.NodeID) ([]types.Domain, error) {
	return Read(hsdb.DB, func(tx *gorm.DB) ([]types.Domain, error) {
		return ListVerifiedDomainsForNode(tx, nodeID)
	})
}

func ListVerifiedDomainsForNode(tx *gorm.DB, nodeID types.NodeID) ([]types.Domain, error) {
	var domains []types.Domain
	if err := tx.Where("node_id = ? AND verified = ?", nodeID, true).Find(&domains).Error; err != nil {
		return nil, fmt.Errorf("listing verified domains for node: %w", err)
	}
	return domains, nil
}

func (hsdb *HSDatabase) DeleteDomain(name string) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return DeleteDomain(tx, name)
	})
}

// DeleteDomain removes a domain entry. Rejects deletion of zones that
// have child domains.
func DeleteDomain(tx *gorm.DB, name string) error {
	domain, err := GetDomainByName(tx, name)
	if err != nil {
		return err
	}

	// If this is a zone, check for children
	if domain.IsZone() {
		var count int64
		suffix := "." + domain.Domain
		tx.Model(&types.Domain{}).
			Where("domain LIKE ? AND domain != ?", "%"+suffix, domain.Domain).
			Count(&count)
		if count > 0 {
			return ErrZoneHasChildren
		}
	}

	if err := tx.Unscoped().Delete(domain).Error; err != nil {
		return fmt.Errorf("deleting domain: %w", err)
	}
	return nil
}

func (hsdb *HSDatabase) SetDomainVerified(name string) (*types.Domain, error) {
	return Write(hsdb.DB, func(tx *gorm.DB) (*types.Domain, error) {
		return SetDomainVerified(tx, name)
	})
}

func SetDomainVerified(tx *gorm.DB, name string) (*types.Domain, error) {
	domain, err := GetDomainByName(tx, name)
	if err != nil {
		return nil, err
	}
	domain.Verified = true
	if err := tx.Save(domain).Error; err != nil {
		return nil, fmt.Errorf("verifying domain: %w", err)
	}
	return domain, nil
}

func (hsdb *HSDatabase) ReassignDomain(name string, newNodeID types.NodeID) (*types.Domain, error) {
	return Write(hsdb.DB, func(tx *gorm.DB) (*types.Domain, error) {
		return ReassignDomain(tx, name, newNodeID)
	})
}

func ReassignDomain(tx *gorm.DB, name string, newNodeID types.NodeID) (*types.Domain, error) {
	domain, err := GetDomainByName(tx, name)
	if err != nil {
		return nil, err
	}
	nid := newNodeID
	domain.NodeID = &nid
	if err := tx.Save(domain).Error; err != nil {
		return nil, fmt.Errorf("reassigning domain: %w", err)
	}
	return domain, nil
}

func (hsdb *HSDatabase) FindParentZone(domain string) (*types.Domain, error) {
	return Read(hsdb.DB, func(tx *gorm.DB) (*types.Domain, error) {
		return findParentZone(tx, domain)
	})
}

func (hsdb *HSDatabase) CreateDomainAccess(domainID uint64, userID uint, role string) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return CreateDomainAccess(tx, domainID, userID, role)
	})
}

func CreateDomainAccess(tx *gorm.DB, domainID uint64, userID uint, role string) error {
	access := types.DomainAccess{
		DomainID: domainID,
		UserID:   userID,
		Role:     role,
	}
	if err := tx.Create(&access).Error; err != nil {
		return fmt.Errorf("creating domain access: %w", err)
	}
	return nil
}

func (hsdb *HSDatabase) DeleteDomainAccess(domainID uint64, userID uint) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return DeleteDomainAccess(tx, domainID, userID)
	})
}

func DeleteDomainAccess(tx *gorm.DB, domainID uint64, userID uint) error {
	result := tx.Where("domain_id = ? AND user_id = ?", domainID, userID).
		Unscoped().Delete(&types.DomainAccess{})
	if result.Error != nil {
		return fmt.Errorf("deleting domain access: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("domain access not found")
	}
	return nil
}
