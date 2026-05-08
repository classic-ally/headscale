package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Propagation poll bounds for ACME DNS-01 TXT records. Cloudflare API
// returns 200 on accept, but the record may not yet be visible at the
// zone's authoritative NS. Returning before propagation makes the
// downstream LE order race the validator and land in `invalid`.
const (
	propagationTimeout = 120 * time.Second
	propagationBackoff = 2 * time.Second
)

// Cloudflare implements the DNSProvider interface using the Cloudflare API v4.
type Cloudflare struct {
	apiToken string
	client   *http.Client
	baseURL  string

	mu      sync.Mutex
	zoneIDs map[string]string // cached zone name → zone ID
}

// NewCloudflare creates a new Cloudflare DNS provider.
func NewCloudflare(apiToken string) *Cloudflare {
	return &Cloudflare{
		apiToken: apiToken,
		client:   &http.Client{},
		baseURL:  "https://api.cloudflare.com/client/v4",
		zoneIDs:  make(map[string]string),
	}
}

type cfResponse struct {
	Success bool            `json:"success"`
	Result  json.RawMessage `json:"result"`
}

type cfZone struct {
	ID string `json:"id"`
}

type cfRecord struct {
	ID string `json:"id"`
}

func (c *Cloudflare) do(ctx context.Context, method, path string, body string) (json.RawMessage, error) {
	var reqBody io.Reader
	if body != "" {
		reqBody = strings.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("cloudflare API error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var cfResp cfResponse
	if err := json.Unmarshal(respBody, &cfResp); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}
	if !cfResp.Success {
		return nil, fmt.Errorf("cloudflare API error: %s", string(respBody))
	}

	return cfResp.Result, nil
}

// getZoneID resolves a domain to its Cloudflare zone ID, with caching.
func (c *Cloudflare) getZoneID(ctx context.Context, domain string) (string, error) {
	// Extract zone from domain (last two labels)
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid domain: %s", domain)
	}
	zone := strings.Join(parts[len(parts)-2:], ".")

	c.mu.Lock()
	if id, ok := c.zoneIDs[zone]; ok {
		c.mu.Unlock()
		return id, nil
	}
	c.mu.Unlock()

	result, err := c.do(ctx, http.MethodGet, "/zones?name="+zone, "")
	if err != nil {
		return "", fmt.Errorf("looking up zone %s: %w", zone, err)
	}

	var zones []cfZone
	if err := json.Unmarshal(result, &zones); err != nil {
		return "", fmt.Errorf("parsing zone response: %w", err)
	}
	if len(zones) == 0 {
		return "", fmt.Errorf("zone not found: %s", zone)
	}

	c.mu.Lock()
	c.zoneIDs[zone] = zones[0].ID
	c.mu.Unlock()

	return zones[0].ID, nil
}

// findRecord looks up an existing DNS record by name and type.
func (c *Cloudflare) findRecord(ctx context.Context, zoneID, name, recordType string) (string, error) {
	result, err := c.do(ctx, http.MethodGet,
		fmt.Sprintf("/zones/%s/dns_records?type=%s&name=%s", zoneID, recordType, name), "")
	if err != nil {
		return "", err
	}

	var records []cfRecord
	if err := json.Unmarshal(result, &records); err != nil {
		return "", fmt.Errorf("parsing records: %w", err)
	}
	if len(records) == 0 {
		return "", nil
	}
	return records[0].ID, nil
}

func (c *Cloudflare) SetRecord(ctx context.Context, name, recordType, value string) error {
	zoneID, err := c.getZoneID(ctx, name)
	if err != nil {
		return err
	}

	body := fmt.Sprintf(`{"type":"%s","name":"%s","content":"%s","ttl":120}`, recordType, name, value)

	recordID, err := c.findRecord(ctx, zoneID, name, recordType)
	if err != nil {
		return fmt.Errorf("checking existing record: %w", err)
	}

	if recordID != "" {
		_, err = c.do(ctx, http.MethodPut,
			fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, recordID), body)
	} else {
		_, err = c.do(ctx, http.MethodPost,
			fmt.Sprintf("/zones/%s/dns_records", zoneID), body)
	}

	if err != nil {
		return fmt.Errorf("setting DNS record: %w", err)
	}

	// Wait for the record to be visible at the zone's authoritative NS
	// before returning, so an ACME validator polled by the caller does not
	// race propagation. Only TXT needs this — A/AAAA/CNAME callers do not
	// trigger an immediate downstream check.
	if recordType == "TXT" {
		if err := c.waitForPropagation(ctx, name, value); err != nil {
			return fmt.Errorf("waiting for TXT propagation: %w", err)
		}
	}

	return nil
}

// waitForPropagation polls the zone's authoritative NS for `name` (TXT)
// until an entry matching `value` is observed, or the timeout elapses.
// Resolution goes directly to the auth NS to bypass any caching resolver.
func (c *Cloudflare) waitForPropagation(ctx context.Context, name, value string) error {
	parts := strings.Split(name, ".")
	if len(parts) < 2 {
		return fmt.Errorf("invalid record name: %s", name)
	}
	zone := strings.Join(parts[len(parts)-2:], ".")

	nss, err := net.DefaultResolver.LookupNS(ctx, zone)
	if err != nil || len(nss) == 0 {
		return fmt.Errorf("looking up NS for %s: %w", zone, err)
	}

	nsAddr := strings.TrimSuffix(nss[0].Host, ".") + ":53"
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", nsAddr)
		},
	}

	deadline := time.Now().Add(propagationTimeout)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		txts, err := resolver.LookupTXT(ctx, name)
		if err == nil {
			for _, t := range txts {
				if t == value {
					return nil
				}
			}
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("TXT %s with value %q not visible at %s within %s", name, value, nsAddr, propagationTimeout)
		}
		time.Sleep(propagationBackoff)
	}
}

func (c *Cloudflare) DeleteRecord(ctx context.Context, name, recordType string) error {
	zoneID, err := c.getZoneID(ctx, name)
	if err != nil {
		return err
	}

	recordID, err := c.findRecord(ctx, zoneID, name, recordType)
	if err != nil {
		return fmt.Errorf("finding record to delete: %w", err)
	}
	if recordID == "" {
		return nil // nothing to delete
	}

	_, err = c.do(ctx, http.MethodDelete,
		fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, recordID), "")
	if err != nil {
		return fmt.Errorf("deleting DNS record: %w", err)
	}
	return nil
}
