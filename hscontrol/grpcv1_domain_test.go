package hscontrol

import (
	"context"
	"testing"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// createUserNode registers a user-owned node via an untagged pre-auth key and
// returns its NodeID, for domain handlers that bind domains to a node.
func createUserNode(
	t *testing.T,
	app *Headscale,
	userName, hostname string,
) types.NodeID {
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

	node, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found)

	return node.ID()
}

func TestRegisterDomain_WithProviderAutoVerifies(t *testing.T) {
	app := createTestApp(t)
	api := newHeadscaleV1APIServer(app)

	resp, err := api.RegisterDomain(context.Background(), &v1.RegisterDomainRequest{
		Domain:   "bw.bentley.sh",
		Provider: "cloudflare",
		ApiToken: "secret",
	})
	require.NoError(t, err)
	assert.Equal(t, "bw.bentley.sh", resp.GetDomain().GetDomain())
	assert.True(
		t,
		resp.GetDomain().GetVerified(),
		"provider credentials should auto-verify",
	)
}

func TestRegisterDomain_Duplicate(t *testing.T) {
	// A bare re-registration (no new provider credentials, no new node
	// binding) has nothing to upsert and must be rejected. Re-registering
	// with provider credentials instead upserts and is covered separately.
	app := createTestApp(t)
	api := newHeadscaleV1APIServer(app)

	req := &v1.RegisterDomainRequest{Domain: "dup.bentley.sh"}
	_, err := api.RegisterDomain(context.Background(), req)
	require.NoError(t, err)

	_, err = api.RegisterDomain(context.Background(), req)
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestRegisterDomain_ProviderUpsert(t *testing.T) {
	// Re-registering an existing domain with provider credentials upserts
	// them rather than failing.
	app := createTestApp(t)
	api := newHeadscaleV1APIServer(app)

	_, err := api.RegisterDomain(
		context.Background(),
		&v1.RegisterDomainRequest{Domain: "ups.bentley.sh"},
	)
	require.NoError(t, err)

	resp, err := api.RegisterDomain(context.Background(), &v1.RegisterDomainRequest{
		Domain:   "ups.bentley.sh",
		Provider: "cloudflare",
		ApiToken: "x",
	})
	require.NoError(t, err)
	assert.True(
		t,
		resp.GetDomain().GetVerified(),
		"upserting provider credentials auto-verifies",
	)
}

func TestRegisterDomain_BoundToNodeUnverified(t *testing.T) {
	app := createTestApp(t)
	api := newHeadscaleV1APIServer(app)
	nodeID := createUserNode(t, app, "alice", "node-a")

	resp, err := api.RegisterDomain(context.Background(), &v1.RegisterDomainRequest{
		Domain: "app.bentley.sh",
		NodeId: uint64(nodeID),
	})
	require.NoError(t, err)
	assert.Equal(t, uint64(nodeID), resp.GetDomain().GetNodeId())
	assert.False(
		t,
		resp.GetDomain().GetVerified(),
		"no provider and no parent zone means pending verification",
	)
}

func TestListDomains(t *testing.T) {
	app := createTestApp(t)
	api := newHeadscaleV1APIServer(app)

	for _, d := range []string{"a.bentley.sh", "b.bentley.sh"} {
		_, err := api.RegisterDomain(
			context.Background(),
			&v1.RegisterDomainRequest{Domain: d, Provider: "cloudflare", ApiToken: "x"},
		)
		require.NoError(t, err)
	}

	resp, err := api.ListDomains(context.Background(), &v1.ListDomainsRequest{})
	require.NoError(t, err)
	assert.Len(t, resp.GetDomains(), 2)
}

func TestVerifyDomain_AlreadyVerified(t *testing.T) {
	// Provider-registered domains are auto-verified, so VerifyDomain returns
	// early without performing a (real) DNS lookup.
	app := createTestApp(t)
	api := newHeadscaleV1APIServer(app)

	_, err := api.RegisterDomain(
		context.Background(),
		&v1.RegisterDomainRequest{
			Domain:   "verified.bentley.sh",
			Provider: "cloudflare",
			ApiToken: "x",
		},
	)
	require.NoError(t, err)

	resp, err := api.VerifyDomain(
		context.Background(),
		&v1.VerifyDomainRequest{Domain: "verified.bentley.sh"},
	)
	require.NoError(t, err)
	assert.True(t, resp.GetDomain().GetVerified())
}

func TestVerifyDomain_NotFound(t *testing.T) {
	app := createTestApp(t)
	api := newHeadscaleV1APIServer(app)

	_, err := api.VerifyDomain(
		context.Background(),
		&v1.VerifyDomainRequest{Domain: "ghost.bentley.sh"},
	)
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestDeleteDomain(t *testing.T) {
	app := createTestApp(t)
	api := newHeadscaleV1APIServer(app)

	_, err := api.RegisterDomain(
		context.Background(),
		&v1.RegisterDomainRequest{
			Domain:   "del.bentley.sh",
			Provider: "cloudflare",
			ApiToken: "x",
		},
	)
	require.NoError(t, err)

	_, err = api.DeleteDomain(
		context.Background(),
		&v1.DeleteDomainRequest{Domain: "del.bentley.sh"},
	)
	require.NoError(t, err)

	resp, err := api.ListDomains(context.Background(), &v1.ListDomainsRequest{})
	require.NoError(t, err)
	assert.Empty(t, resp.GetDomains())
}

func TestDeleteDomain_NotFound(t *testing.T) {
	app := createTestApp(t)
	api := newHeadscaleV1APIServer(app)

	_, err := api.DeleteDomain(
		context.Background(),
		&v1.DeleteDomainRequest{Domain: "nope.bentley.sh"},
	)
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestReassignDomain(t *testing.T) {
	app := createTestApp(t)
	api := newHeadscaleV1APIServer(app)
	node1 := createUserNode(t, app, "u1", "n1")
	node2 := createUserNode(t, app, "u2", "n2")

	_, err := api.RegisterDomain(
		context.Background(),
		&v1.RegisterDomainRequest{Domain: "move.bentley.sh", NodeId: uint64(node1)},
	)
	require.NoError(t, err)

	resp, err := api.ReassignDomain(
		context.Background(),
		&v1.ReassignDomainRequest{Domain: "move.bentley.sh", NodeId: uint64(node2)},
	)
	require.NoError(t, err)
	assert.Equal(t, uint64(node2), resp.GetDomain().GetNodeId())
}

func TestReassignDomain_NotFound(t *testing.T) {
	app := createTestApp(t)
	api := newHeadscaleV1APIServer(app)
	node := createUserNode(t, app, "reassign-user", "rn")

	_, err := api.ReassignDomain(
		context.Background(),
		&v1.ReassignDomainRequest{Domain: "ghost.bentley.sh", NodeId: uint64(node)},
	)
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestSetAndDeleteDomainAccess(t *testing.T) {
	app := createTestApp(t)
	api := newHeadscaleV1APIServer(app)
	user := app.state.CreateUserForTest("access-user")

	_, err := api.RegisterDomain(
		context.Background(),
		&v1.RegisterDomainRequest{
			Domain:   "acl.bentley.sh",
			Provider: "cloudflare",
			ApiToken: "x",
		},
	)
	require.NoError(t, err)

	_, err = api.SetDomainAccess(context.Background(), &v1.SetDomainAccessRequest{
		Domain: "acl.bentley.sh",
		UserId: uint64(user.ID),
		Role:   "editor",
	})
	require.NoError(t, err)

	_, err = api.DeleteDomainAccess(context.Background(), &v1.DeleteDomainAccessRequest{
		Domain: "acl.bentley.sh",
		UserId: uint64(user.ID),
	})
	require.NoError(t, err)
}

func TestSetDomainAccess_DomainNotFound(t *testing.T) {
	app := createTestApp(t)
	api := newHeadscaleV1APIServer(app)

	_, err := api.SetDomainAccess(context.Background(), &v1.SetDomainAccessRequest{
		Domain: "ghost.bentley.sh",
		UserId: 1,
		Role:   "owner",
	})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}
