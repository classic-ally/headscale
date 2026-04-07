package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newMockCloudflare(t *testing.T, handler http.HandlerFunc) *Cloudflare {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	cf := NewCloudflare("test-token")
	cf.baseURL = server.URL

	return cf
}

func cfOK(result any) []byte {
	data, _ := json.Marshal(result)
	resp, _ := json.Marshal(cfResponse{Success: true, Result: data})
	return resp
}

func TestCloudflareSetRecordCreate(t *testing.T) {
	var gotMethod, gotPath, gotBody string

	cf := newMockCloudflare(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path

		switch {
		case r.URL.Path == "/zones" && r.Method == http.MethodGet:
			w.Write(cfOK([]cfZone{{ID: "zone-123"}}))
		case r.URL.Path == "/zones/zone-123/dns_records" && r.Method == http.MethodGet:
			// No existing records
			w.Write(cfOK([]cfRecord{}))
		case r.URL.Path == "/zones/zone-123/dns_records" && r.Method == http.MethodPost:
			body, _ := json.RawMessage(nil), error(nil)
			buf := make([]byte, 1024)
			n, _ := r.Body.Read(buf)
			gotBody = string(buf[:n])
			w.Write(cfOK(body))
		default:
			w.WriteHeader(404)
		}
	})

	err := cf.SetRecord(context.Background(), "_acme-challenge.bw.bentley.sh", "TXT", "challenge-value")
	require.NoError(t, err)
	assert.Equal(t, http.MethodPost, gotMethod)
	assert.Contains(t, gotPath, "/dns_records")
	assert.Contains(t, gotBody, "challenge-value")
}

func TestCloudflareSetRecordUpdate(t *testing.T) {
	var gotMethod, gotPath string

	cf := newMockCloudflare(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path

		switch {
		case r.URL.Path == "/zones" && r.Method == http.MethodGet:
			w.Write(cfOK([]cfZone{{ID: "zone-123"}}))
		case r.URL.Path == "/zones/zone-123/dns_records" && r.Method == http.MethodGet:
			// Existing record
			w.Write(cfOK([]cfRecord{{ID: "rec-456"}}))
		case r.URL.Path == "/zones/zone-123/dns_records/rec-456" && r.Method == http.MethodPut:
			w.Write(cfOK(nil))
		default:
			w.WriteHeader(404)
		}
	})

	err := cf.SetRecord(context.Background(), "test.bentley.sh", "TXT", "new-value")
	require.NoError(t, err)
	assert.Equal(t, http.MethodPut, gotMethod)
	assert.Contains(t, gotPath, "rec-456")
}

func TestCloudflareDeleteRecord(t *testing.T) {
	var gotMethod string

	cf := newMockCloudflare(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method

		switch {
		case r.URL.Path == "/zones" && r.Method == http.MethodGet:
			w.Write(cfOK([]cfZone{{ID: "zone-123"}}))
		case r.URL.Path == "/zones/zone-123/dns_records" && r.Method == http.MethodGet:
			w.Write(cfOK([]cfRecord{{ID: "rec-789"}}))
		case r.URL.Path == "/zones/zone-123/dns_records/rec-789" && r.Method == http.MethodDelete:
			w.Write(cfOK(nil))
		default:
			w.WriteHeader(404)
		}
	})

	err := cf.DeleteRecord(context.Background(), "test.bentley.sh", "TXT")
	require.NoError(t, err)
	assert.Equal(t, http.MethodDelete, gotMethod)
}

func TestCloudflareZoneNotFound(t *testing.T) {
	cf := newMockCloudflare(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write(cfOK([]cfZone{})) // empty result
	})

	err := cf.SetRecord(context.Background(), "test.unknown.dev", "TXT", "value")
	assert.ErrorContains(t, err, "zone not found")
}

func TestCloudflareAuthFailure(t *testing.T) {
	cf := newMockCloudflare(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"success":false,"errors":[{"message":"Invalid API Token"}]}`))
	})

	err := cf.SetRecord(context.Background(), "test.bentley.sh", "TXT", "value")
	assert.ErrorContains(t, err, "401")
}

func TestCloudflareZoneIDCaching(t *testing.T) {
	callCount := 0

	cf := newMockCloudflare(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/zones" && r.Method == http.MethodGet:
			callCount++
			w.Write(cfOK([]cfZone{{ID: "zone-123"}}))
		case r.Method == http.MethodGet:
			w.Write(cfOK([]cfRecord{}))
		case r.Method == http.MethodPost:
			w.Write(cfOK(nil))
		}
	})

	ctx := context.Background()
	_ = cf.SetRecord(ctx, "a.bentley.sh", "TXT", "v1")
	_ = cf.SetRecord(ctx, "b.bentley.sh", "TXT", "v2")

	// Zone lookup should only happen once (cached)
	assert.Equal(t, 1, callCount)
}

func TestCloudflareAuthHeader(t *testing.T) {
	var gotAuth string

	cf := newMockCloudflare(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Write(cfOK([]cfZone{{ID: "z"}}))
	})

	_ = cf.SetRecord(context.Background(), "test.bentley.sh", "TXT", "v")
	assert.Equal(t, "Bearer test-token", gotAuth)
}
