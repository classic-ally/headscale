package state

import (
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testDomainProvider = "cloudflare"

func newTestState(t *testing.T) *State {
	t.Helper()

	tmp := t.TempDir()
	cfg := &types.Config{
		ServerURL:           "http://localhost:8080",
		NoisePrivateKeyPath: tmp + "/noise_private.key",
		Database: types.DatabaseConfig{
			Type:   "sqlite3",
			Sqlite: types.SqliteConfig{Path: tmp + "/state_test.db"},
		},
		Policy: types.PolicyConfig{Mode: types.PolicyModeDB},
		Tuning: types.Tuning{
			BatchChangeDelay: 100 * time.Millisecond,
			BatcherWorkers:   1,
		},
	}

	s, err := NewState(cfg)
	require.NoError(t, err)

	return s
}

func TestState_RegisterDomain_ProviderAndNodeEmitsCertChange(t *testing.T) {
	s := newTestState(t)
	user := s.CreateUserForTest("alice")
	node := s.CreateNodeForTest(user, "node-a")
	nid := node.ID

	provider, token := testDomainProvider, "secret"
	d, c, err := s.RegisterDomain("app.bentley.sh", &nid, &provider, &token)
	require.NoError(t, err)

	assert.True(t, d.Verified, "provider credentials auto-verify")
	assert.Equal(t, nid, c.TargetNode)
	assert.True(t, c.IncludeDNS)
	assert.True(t, c.IncludeSelf)
}

func TestState_RegisterDomain_BoundUnverifiedNoChange(t *testing.T) {
	s := newTestState(t)
	user := s.CreateUserForTest("bob")
	node := s.CreateNodeForTest(user, "node-b")
	nid := node.ID

	d, c, err := s.RegisterDomain("plain.bentley.sh", &nid, nil, nil)
	require.NoError(t, err)

	assert.False(t, d.Verified, "no provider and no parent zone leaves it pending")
	assert.Equal(t, change.Change{}, c, "unverified registration emits no change")
}

func TestState_VerifyDomain_AlreadyVerifiedSkipsDNS(t *testing.T) {
	// Already-verified domains return early without the real net.LookupTXT.
	s := newTestState(t)
	provider, token := testDomainProvider, "x"
	_, _, err := s.RegisterDomain("verified.bentley.sh", nil, &provider, &token)
	require.NoError(t, err)

	d, c, err := s.VerifyDomain("verified.bentley.sh")
	require.NoError(t, err)
	assert.True(t, d.Verified)
	assert.Equal(t, change.Change{}, c)
}

func TestState_VerifyDomain_NotFound(t *testing.T) {
	s := newTestState(t)

	_, _, err := s.VerifyDomain("ghost.bentley.sh")
	require.Error(t, err)
}

func TestState_DeleteDomain_NodeBoundEmitsCertChange(t *testing.T) {
	s := newTestState(t)
	user := s.CreateUserForTest("carol")
	node := s.CreateNodeForTest(user, "node-c")
	nid := node.ID

	provider, token := testDomainProvider, "x"
	_, _, err := s.RegisterDomain("del.bentley.sh", &nid, &provider, &token)
	require.NoError(t, err)

	c, err := s.DeleteDomain("del.bentley.sh")
	require.NoError(t, err)
	assert.Equal(t, nid, c.TargetNode)
	assert.True(t, c.IncludeDNS)
}

func TestState_ReassignDomain_EmitsDNSChange(t *testing.T) {
	s := newTestState(t)
	user := s.CreateUserForTest("dave")
	n1 := s.CreateNodeForTest(user, "node-d1")
	n2 := s.CreateNodeForTest(user, "node-d2")
	id1, id2 := n1.ID, n2.ID

	provider, token := testDomainProvider, "x"
	_, _, err := s.RegisterDomain("move.bentley.sh", &id1, &provider, &token)
	require.NoError(t, err)

	updated, c, err := s.ReassignDomain("move.bentley.sh", id2)
	require.NoError(t, err)
	require.NotNil(t, updated.NodeID)
	assert.Equal(t, id2, *updated.NodeID)
	assert.True(t, c.IncludeDNS)
}

func TestState_FindParentZone(t *testing.T) {
	s := newTestState(t)
	provider, token := testDomainProvider, "x"
	_, _, err := s.RegisterDomain("bentley.sh", nil, &provider, &token)
	require.NoError(t, err)

	zone, err := s.FindParentZone("sub.bentley.sh")
	require.NoError(t, err)
	require.NotNil(t, zone)
	assert.Equal(t, "bentley.sh", zone.Domain)

	none, err := s.FindParentZone("orphan.example.org")
	require.NoError(t, err)
	assert.Nil(t, none, "no zone with credentials means no parent")
}

func TestState_VerifiedDomainsForNode(t *testing.T) {
	s := newTestState(t)
	user := s.CreateUserForTest("erin")
	node := s.CreateNodeForTest(user, "node-e")
	nid := node.ID

	provider, token := testDomainProvider, "x"
	_, _, err := s.RegisterDomain("svc.bentley.sh", &nid, &provider, &token)
	require.NoError(t, err)

	assert.Equal(t, []string{"svc.bentley.sh"}, s.VerifiedDomainsForNode(nid))
}

func TestState_AllVerifiedDomainRecords(t *testing.T) {
	s := newTestState(t)
	user := s.CreateUserForTest("frank")
	node := s.CreateNodeForTest(user, "node-f")
	nid := node.ID

	provider, token := testDomainProvider, "x"
	_, _, err := s.RegisterDomain("rec.bentley.sh", &nid, &provider, &token)
	require.NoError(t, err)

	records := s.AllVerifiedDomainRecords()
	require.Len(t, records, 1)
	assert.Equal(t, "rec.bentley.sh", records[0].Domain)
}
