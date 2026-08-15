package hscontrol

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// The Noise handshake accepts any machine key without checking registration,
// so /machine/set-dns is reachable by any peer that can speak TS2021 to the
// control plane - which, for a publicly reachable server_url, means anyone on
// the internet. The handler previously wrote whatever record it was handed
// using the zone's stored DNS provider credentials, which made every zone
// headscale holds a token for writable by an unauthenticated caller: TXT for
// an ACME DNS-01 challenge on any name (yielding certificates), or an A/MX
// record repointing mail or a funnel host.
//
// The tests below pin the two checks that close that hole: the caller must
// prove it is a registered node, and the record it asks for must fall inside
// that node's own certificate allowlist.

// registerTestNode registers a node with a pre-auth key and returns its view
// along with the keys, so a test can build a noiseServer that legitimately
// speaks for it - or one that impersonates it.
func registerTestNode(
	t *testing.T,
	app *Headscale,
	userName, hostname string,
) (types.NodeView, key.MachinePrivate, key.NodePrivate) {
	t.Helper()

	user := app.state.CreateUserForTest(userName)
	pak, err := app.state.CreatePreAuthKey(user.TypedID(), false, false, nil, nil)
	require.NoError(t, err)

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	_, err = app.handleRegisterWithAuthKey(tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey:  nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: hostname},
	}, machineKey.Public())
	require.NoError(t, err)

	nv, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found)

	return nv, machineKey, nodeKey
}

// newSetDNSTestApp builds an app with the certificates feature enabled and
// set_dns_command pointed at a recorder script. No domain rows carry provider
// credentials, so an authorized request takes the set_dns_command branch and
// leaves a line behind rather than reaching out to a real DNS provider. The
// returned function reports the writes that actually happened, which is how
// each test distinguishes "rejected with a status code" from "rejected only
// after the record was already written".
func newSetDNSTestApp(t *testing.T) (*Headscale, func() []string) {
	t.Helper()

	app := createTestApp(t)
	app.cfg.BaseDomain = "icefox.xyz"
	app.cfg.CertificatesFeatureConfig.Enabled = true

	dir := t.TempDir()
	recordPath := filepath.Join(dir, "writes")
	scriptPath := filepath.Join(dir, "set-dns.sh")

	script := "#!/bin/sh\nprintf '%s %s %s\\n' \"$1\" \"$2\" \"$3\" >> " + recordPath + "\n"
	require.NoError(t, os.WriteFile(scriptPath, []byte(script), 0o700))

	app.cfg.CertificatesFeatureConfig.SetDNSCommand = scriptPath

	return app, func() []string {
		t.Helper()

		data, err := os.ReadFile(recordPath)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		require.NoError(t, err)

		return strings.Split(strings.TrimSpace(string(data)), "\n")
	}
}

// postSetDNS drives SetDNSHandler directly, standing in for a request that
// arrived over an established Noise session whose peer key is ns.machineKey.
func postSetDNS(
	t *testing.T,
	ns *noiseServer,
	req tailcfg.SetDNSRequest,
) *httptest.ResponseRecorder {
	t.Helper()

	body, err := json.Marshal(req)
	require.NoError(t, err)

	recorder := httptest.NewRecorder()
	ns.SetDNSHandler(
		recorder,
		httptest.NewRequest(http.MethodPost, "/machine/set-dns", bytes.NewReader(body)),
	)

	return recorder
}

func TestSetDNSHandler_RejectsUnregisteredCaller(t *testing.T) {
	app, writes := newSetDNSTestApp(t)

	// An attacker completes the Noise handshake with keys it generated
	// itself and never registered. This is the base case for the whole
	// vulnerability: no credential of any kind was presented.
	attackerMachine := key.NewMachine()
	attackerNode := key.NewNode()

	ns := &noiseServer{headscale: app, machineKey: attackerMachine.Public()}

	resp := postSetDNS(t, ns, tailcfg.SetDNSRequest{
		NodeKey: attackerNode.Public(),
		Name:    "_acme-challenge.mail.bentley.sh",
		Type:    "TXT",
		Value:   "attacker-controlled",
	})

	assert.Equal(t, http.StatusNotFound, resp.Code)
	assert.Empty(t, writes(), "an unregistered caller must not reach the DNS write")
}

func TestSetDNSHandler_RejectsBorrowedNodeKey(t *testing.T) {
	app, writes := newSetDNSTestApp(t)

	victim, _, victimNodeKey := registerTestNode(t, app, "victim", "thor")

	// Node keys are not secret - they are handed to every peer in the
	// netmap - so quoting one must not be enough. The machine key is what
	// the Noise session actually proves, and it has to match.
	attackerMachine := key.NewMachine()
	ns := &noiseServer{headscale: app, machineKey: attackerMachine.Public()}

	resp := postSetDNS(t, ns, tailcfg.SetDNSRequest{
		NodeKey: victimNodeKey.Public(),
		Name:    "_acme-challenge." + victim.Hostname() + ".icefox.xyz",
		Type:    "TXT",
		Value:   "attacker-controlled",
	})

	assert.Equal(t, http.StatusNotFound, resp.Code)
	assert.Empty(t, writes(), "a mismatched machine key must not reach the DNS write")
}

func TestSetDNSHandler_RejectsDomainOfAnotherNode(t *testing.T) {
	app, writes := newSetDNSTestApp(t)

	_, callerMachine, callerNodeKey := registerTestNode(t, app, "caller", "laptop")
	other, _, _ := registerTestNode(t, app, "other", "thor")

	// A registered node is still confined to its own names. Registration
	// is cheap - a pre-auth key, or any OIDC user allowed to join - so
	// without this check the hole merely shrinks from "anyone" to "anyone
	// who can get one node onto the tailnet".
	ns := &noiseServer{headscale: app, machineKey: callerMachine.Public()}

	resp := postSetDNS(t, ns, tailcfg.SetDNSRequest{
		NodeKey: callerNodeKey.Public(),
		Name:    "_acme-challenge." + other.Hostname() + ".icefox.xyz",
		Type:    "TXT",
		Value:   "attacker-controlled",
	})

	assert.Equal(t, http.StatusForbidden, resp.Code)
	assert.Empty(t, writes(), "a node must not write DNS for another node's name")
}

func TestSetDNSHandler_RejectsNonTXTRecord(t *testing.T) {
	app, writes := newSetDNSTestApp(t)

	caller, callerMachine, callerNodeKey := registerTestNode(t, app, "caller", "laptop")

	// Entitlement to a certificate for a name is not entitlement to
	// repoint it. The endpoint exists for DNS-01 challenges, so an A
	// record is out of scope even on a name the caller owns.
	ns := &noiseServer{headscale: app, machineKey: callerMachine.Public()}

	resp := postSetDNS(t, ns, tailcfg.SetDNSRequest{
		NodeKey: callerNodeKey.Public(),
		Name:    caller.Hostname() + ".icefox.xyz",
		Type:    "A",
		Value:   "203.0.113.7",
	})

	assert.Equal(t, http.StatusForbidden, resp.Code)
	assert.Empty(t, writes(), "only TXT records may be written through set-dns")
}

func TestSetDNSHandler_AllowsOwnACMEChallenge(t *testing.T) {
	app, writes := newSetDNSTestApp(t)

	caller, callerMachine, callerNodeKey := registerTestNode(t, app, "caller", "thor")

	ns := &noiseServer{headscale: app, machineKey: callerMachine.Public()}

	name := "_acme-challenge." + caller.Hostname() + ".icefox.xyz"
	resp := postSetDNS(t, ns, tailcfg.SetDNSRequest{
		NodeKey: callerNodeKey.Public(),
		Name:    name,
		Type:    "TXT",
		Value:   "challenge-token",
	})

	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(
		t,
		[]string{name + " TXT challenge-token"},
		writes(),
		"a node's own challenge must still be written",
	)
}

func TestAuthorizeSetDNS(t *testing.T) {
	t.Parallel()

	// The allowlist a node is handed in its netmap: its MagicDNS name plus
	// the verified domains bound to it. Everything else in the zone -
	// including names bound to other nodes and the apex itself - is out.
	certDomains := []string{"thor.icefox.xyz", "git.bentley.sh"}

	tests := []struct {
		name       string
		record     string
		recordType string
		wantErr    error
	}{
		{
			name:       "_acme-challenge.git.bentley.sh",
			record:     "_acme-challenge.git.bentley.sh",
			recordType: "TXT",
		},
		{
			name:       "bare domain without the challenge label",
			record:     "git.bentley.sh",
			recordType: "TXT",
		},
		{
			name:       "magicdns name of the node itself",
			record:     "_acme-challenge.thor.icefox.xyz",
			recordType: "TXT",
		},
		{
			name:       "mixed case and a trailing root label",
			record:     "_ACME-Challenge.Git.Bentley.SH.",
			recordType: "txt",
		},
		{
			name:       "sibling name in the same zone",
			record:     "_acme-challenge.bw.bentley.sh",
			recordType: "TXT",
			wantErr:    errSetDNSUnauthorizedName,
		},
		{
			name:       "zone apex",
			record:     "_acme-challenge.bentley.sh",
			recordType: "TXT",
			wantErr:    errSetDNSUnauthorizedName,
		},
		{
			// An allowed name must match whole labels. A suffix test
			// would let "evil-git.bentley.sh" through, and a prefix
			// test would let "git.bentley.sh.evil.example" through.
			name:       "name that merely contains an allowed one",
			record:     "_acme-challenge.evil-git.bentley.sh",
			recordType: "TXT",
			wantErr:    errSetDNSUnauthorizedName,
		},
		{
			name:       "allowed name as a prefix of an attacker's",
			record:     "_acme-challenge.git.bentley.sh.evil.example",
			recordType: "TXT",
			wantErr:    errSetDNSUnauthorizedName,
		},
		{
			// Stripping the challenge label repeatedly would let a
			// caller smuggle an extra layer past the comparison.
			name:       "doubled challenge label",
			record:     "_acme-challenge._acme-challenge.git.bentley.sh",
			recordType: "TXT",
			wantErr:    errSetDNSUnauthorizedName,
		},
		{
			name:       "A record on an allowed name",
			record:     "git.bentley.sh",
			recordType: "A",
			wantErr:    errSetDNSUnsupportedType,
		},
		{
			name:       "MX record on an allowed name",
			record:     "bentley.sh",
			recordType: "MX",
			wantErr:    errSetDNSUnsupportedType,
		},
		{
			name:       "empty record type",
			record:     "git.bentley.sh",
			recordType: "",
			wantErr:    errSetDNSUnsupportedType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := authorizeSetDNS(tt.record, tt.recordType, certDomains)
			if tt.wantErr == nil {
				assert.NoError(t, err)

				return
			}

			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestAuthorizeSetDNS_EmptyAllowlist(t *testing.T) {
	t.Parallel()

	// A node with no cert domains - no MagicDNS FQDN and nothing bound to
	// it - can write nothing, rather than everything.
	err := authorizeSetDNS("_acme-challenge.git.bentley.sh", "TXT", nil)
	assert.ErrorIs(t, err, errSetDNSUnauthorizedName)
}
