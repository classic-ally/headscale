package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errTestLookup is a static lookup failure for propagation tests.
var errTestLookup = errors.New("nxdomain")

// fakeResolver is a txtResolver backed by a function, letting tests control
// what each propagation poll observes without touching real DNS.
type fakeResolver func(name string) ([]string, error)

func (f fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	return f(name)
}

// newMockCloudflare returns a Cloudflare provider wired to an httptest server
// running handler. TXT writes (POST/PUT) are mirrored into an in-memory map
// that the injected resolver reads from, so waitForPropagation observes the
// record immediately instead of polling the real public resolvers. Tests that
// need to drive propagation directly can overwrite cf.resolvers afterwards.
func newMockCloudflare(t *testing.T, handler http.HandlerFunc) *Cloudflare {
	t.Helper()

	var mu sync.Mutex

	propagated := map[string][]string{}

	wrapped := func(w http.ResponseWriter, r *http.Request) {
		if (r.Method == http.MethodPost || r.Method == http.MethodPut) &&
			r.Body != nil {
			body, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(body))

			var rec struct {
				Name    string `json:"name"`
				Content string `json:"content"`
			}
			if json.Unmarshal(body, &rec) == nil && rec.Name != "" {
				mu.Lock()

				propagated[rec.Name] = append(propagated[rec.Name], rec.Content)
				mu.Unlock()
			}
		}

		handler(w, r)
	}

	server := httptest.NewServer(http.HandlerFunc(wrapped))
	t.Cleanup(server.Close)

	cf := NewCloudflare("test-token")
	cf.baseURL = server.URL
	cf.resolvers = []txtResolver{fakeResolver(func(name string) ([]string, error) {
		mu.Lock()
		defer mu.Unlock()

		return propagated[name], nil
	})}
	cf.propagationTimeoutOverride = time.Second
	cf.propagationBackoffOverride = 5 * time.Millisecond

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

	err := cf.SetRecord(
		context.Background(),
		"_acme-challenge.bw.bentley.sh",
		"TXT",
		"challenge-value",
	)
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

func newPropagationCloudflare(resolvers ...txtResolver) *Cloudflare {
	cf := NewCloudflare("test-token")
	cf.resolvers = resolvers
	cf.propagationTimeoutOverride = 100 * time.Millisecond
	cf.propagationBackoffOverride = 2 * time.Millisecond

	return cf
}

func TestWaitForPropagationAllVisible(t *testing.T) {
	cf := newPropagationCloudflare(
		fakeResolver(func(string) ([]string, error) { return []string{"val"}, nil }),
		fakeResolver(
			func(string) ([]string, error) { return []string{"junk", "val"}, nil },
		),
	)

	require.NoError(
		t,
		cf.waitForPropagation(context.Background(), "x.bentley.sh", "val"),
	)
}

func TestWaitForPropagationPartialVisibility(t *testing.T) {
	// First resolver sees the value, second never does: must time out and
	// name the missing resolver, quickly (no real-network dependency).
	cf := newPropagationCloudflare(
		fakeResolver(func(string) ([]string, error) { return []string{"val"}, nil }),
		fakeResolver(func(string) ([]string, error) { return []string{"stale"}, nil }),
	)

	start := time.Now()
	err := cf.waitForPropagation(context.Background(), "x.bentley.sh", "val")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not visible")
	assert.Contains(t, err.Error(), propagationResolvers[1])
	assert.Less(t, time.Since(start), time.Second)
}

func TestWaitForPropagationTimeout(t *testing.T) {
	// No resolver ever observes the value (lookup errors): must time out fast.
	cf := newPropagationCloudflare(
		fakeResolver(func(string) ([]string, error) { return nil, errTestLookup }),
	)

	start := time.Now()
	err := cf.waitForPropagation(context.Background(), "x.bentley.sh", "val")
	require.Error(t, err)
	assert.Less(t, time.Since(start), time.Second)
}

func TestWaitForPropagationContextCancelled(t *testing.T) {
	cf := newPropagationCloudflare(
		fakeResolver(func(string) ([]string, error) { return nil, nil }),
	)
	cf.propagationTimeoutOverride = time.Minute // would hang if ctx ignored

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := cf.waitForPropagation(ctx, "x.bentley.sh", "val")
	require.ErrorIs(t, err, context.Canceled)
}

func TestSetRecordNonTXTSkipsPropagation(t *testing.T) {
	cf := newMockCloudflare(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/zones" && r.Method == http.MethodGet:
			_, _ = w.Write(cfOK([]cfZone{{ID: "zone-123"}}))
		case r.Method == http.MethodGet:
			_, _ = w.Write(cfOK([]cfRecord{}))
		case r.Method == http.MethodPost:
			_, _ = w.Write(cfOK(nil))
		}
	})

	// Replace the resolver with one that fails the test if propagation runs.
	cf.resolvers = []txtResolver{fakeResolver(func(string) ([]string, error) {
		t.Error("waitForPropagation must not run for non-TXT records")
		return nil, nil
	})}

	require.NoError(
		t,
		cf.SetRecord(context.Background(), "host.bentley.sh", "A", "1.2.3.4"),
	)
}
