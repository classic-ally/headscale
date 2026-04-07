package providers

import (
	"context"
	"fmt"
)

// DNSProvider manages DNS records for ACME challenges and domain verification.
type DNSProvider interface {
	SetRecord(ctx context.Context, name, recordType, value string) error
	DeleteRecord(ctx context.Context, name, recordType string) error
}

// New creates a DNS provider by name with the given API token.
func New(providerName, apiToken string) (DNSProvider, error) {
	switch providerName {
	case "cloudflare":
		return NewCloudflare(apiToken), nil
	default:
		return nil, fmt.Errorf("unsupported DNS provider: %s", providerName)
	}
}
