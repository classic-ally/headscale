package types

import (
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/rs/zerolog"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// DomainRecord represents a domain-to-IP mapping, used to inject verified
// domains into DNS ExtraRecords for tailnet resolution.
type DomainRecord struct {
	Domain string
	IPv4   string
	IPv6   string
}

// Domain represents a DNS domain registered in headscale.
// Zone entries have Provider + APIToken set and NodeID nil.
// Domain entries have NodeID set and inherit zone credentials from their parent.
type Domain struct {
	ID          uint64  `gorm:"primaryKey;autoIncrement"`
	Domain      string  `gorm:"uniqueIndex;not null"`
	NodeID      *NodeID
	Node        *Node   `gorm:"constraint:OnDelete:CASCADE;"`
	Provider    *string
	APIToken    *string
	Verified    bool    `gorm:"default:false"`
	VerifyToken *string
	CreatedAt   time.Time
}

// IsZone returns true if this domain entry has DNS provider credentials.
func (d *Domain) IsZone() bool {
	return d.Provider != nil && *d.Provider != ""
}

// Proto converts the domain to its protobuf representation.
// APIToken is deliberately never included (write-only).
func (d *Domain) Proto() *v1.Domain {
	if d == nil {
		return nil
	}

	proto := &v1.Domain{
		Id:        uint64(d.ID),
		Domain:    d.Domain,
		Verified:  d.Verified,
		CreatedAt: timestamppb.New(d.CreatedAt),
	}

	if d.NodeID != nil {
		proto.NodeId = uint64(*d.NodeID)
	}

	if d.Provider != nil {
		proto.Provider = *d.Provider
	}

	if d.VerifyToken != nil {
		proto.VerifyToken = *d.VerifyToken
	}

	return proto
}

func (d *Domain) MarshalZerologObject(e *zerolog.Event) {
	if d == nil {
		return
	}
	e.Uint64("domain_id", d.ID)
	e.Str("domain", d.Domain)
	e.Bool("verified", d.Verified)
	if d.NodeID != nil {
		e.Uint64("node_id", uint64(*d.NodeID))
	}
	if d.Provider != nil {
		e.Str("provider", *d.Provider)
	}
}

// DomainAccess tracks which users can manage a domain.
type DomainAccess struct {
	ID        uint64 `gorm:"primaryKey;autoIncrement"`
	DomainID  uint64 `gorm:"not null"`
	Domain    Domain `gorm:"constraint:OnDelete:CASCADE;"`
	UserID    uint   `gorm:"not null"`
	User      User   `gorm:"constraint:OnDelete:CASCADE;"`
	Role      string `gorm:"not null;default:'user'"`
	CreatedAt time.Time
}

func (DomainAccess) TableName() string { return "domain_access" }

func (da *DomainAccess) Proto() *v1.DomainAccess {
	if da == nil {
		return nil
	}
	return &v1.DomainAccess{
		Id:        uint64(da.ID),
		DomainId:  uint64(da.DomainID),
		UserId:    uint64(da.UserID),
		Role:      da.Role,
		CreatedAt: timestamppb.New(da.CreatedAt),
	}
}

func (da *DomainAccess) MarshalZerologObject(e *zerolog.Event) {
	if da == nil {
		return
	}
	e.Uint64("domain_access_id", da.ID)
	e.Uint64("domain_id", da.DomainID)
	e.Uint("user_id", da.UserID)
	e.Str("role", da.Role)
}
