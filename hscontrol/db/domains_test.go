package db

import (
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func strp(s string) *string { return &s }

func TestCreateDomain(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	user := db.CreateUserForTest("test")
	node := db.CreateNodeForTest(user, "testnode")

	domain, err := db.CreateDomain(types.Domain{
		Domain: "test.example.com",
		NodeID: &node.ID,
	})
	require.NoError(t, err)
	assert.Equal(t, "test.example.com", domain.Domain)
	assert.Equal(t, node.ID, *domain.NodeID)
	assert.False(t, domain.Verified)
	assert.NotNil(t, domain.VerifyToken)
}

func TestCreateDomainZone(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	zone, err := db.CreateDomain(types.Domain{
		Domain:   "example.com",
		Provider: strp("cloudflare"),
		APIToken: strp("cf-token-123"),
	})
	require.NoError(t, err)
	assert.Equal(t, "example.com", zone.Domain)
	assert.True(t, zone.IsZone())
	assert.Nil(t, zone.NodeID)
}

func TestCreateDomainDuplicate(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	user := db.CreateUserForTest("test")
	node := db.CreateNodeForTest(user, "testnode")

	_, err = db.CreateDomain(types.Domain{
		Domain: "dup.example.com",
		NodeID: &node.ID,
	})
	require.NoError(t, err)

	_, err = db.CreateDomain(types.Domain{
		Domain: "dup.example.com",
		NodeID: &node.ID,
	})
	assert.ErrorIs(t, err, ErrDomainExists)
}

func TestCreateDomainZoneUpsert(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	zone, err := db.CreateDomain(types.Domain{
		Domain:   "example.com",
		Provider: strp("cloudflare"),
		APIToken: strp("old-token"),
	})
	require.NoError(t, err)

	updated, err := db.CreateDomain(types.Domain{
		Domain:   "example.com",
		Provider: strp("cloudflare"),
		APIToken: strp("new-token"),
	})
	require.NoError(t, err)
	assert.Equal(t, zone.ID, updated.ID)
	assert.Equal(t, "new-token", *updated.APIToken)
}

func TestCreateDomainBindNodeToExistingZone(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	user := db.CreateUserForTest("test")
	node := db.CreateNodeForTest(user, "desktop")

	// Create zone first
	zone, err := db.CreateDomain(types.Domain{
		Domain:   "wolfson.bar",
		Provider: strp("cloudflare"),
		APIToken: strp("token"),
	})
	require.NoError(t, err)
	assert.Nil(t, zone.NodeID)

	// Bind node to existing zone
	updated, err := db.CreateDomain(types.Domain{
		Domain: "wolfson.bar",
		NodeID: &node.ID,
	})
	require.NoError(t, err)
	assert.Equal(t, zone.ID, updated.ID)
	assert.Equal(t, node.ID, *updated.NodeID)
	assert.True(t, updated.IsZone()) // Still has credentials
}

func TestGetDomainByName(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	_, err = db.GetDomainByName("nonexistent.com")
	assert.ErrorIs(t, err, ErrDomainNotFound)

	_, err = db.CreateDomain(types.Domain{
		Domain:   "found.example.com",
		Provider: strp("cloudflare"),
		APIToken: strp("token"),
	})
	require.NoError(t, err)

	domain, err := db.GetDomainByName("found.example.com")
	require.NoError(t, err)
	assert.Equal(t, "found.example.com", domain.Domain)
}

func TestListDomains(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	user := db.CreateUserForTest("test")
	node := db.CreateNodeForTest(user, "testnode")

	_, err = db.CreateDomain(types.Domain{
		Domain:   "example.com",
		Provider: strp("cloudflare"),
		APIToken: strp("token"),
	})
	require.NoError(t, err)

	_, err = db.CreateDomain(types.Domain{
		Domain: "app.example.com",
		NodeID: &node.ID,
	})
	require.NoError(t, err)

	// List all
	domains, err := db.ListDomains(nil, nil)
	require.NoError(t, err)
	assert.Len(t, domains, 2)

	// List by node
	domains, err = db.ListDomains(&node.ID, nil)
	require.NoError(t, err)
	assert.Len(t, domains, 1)
	assert.Equal(t, "app.example.com", domains[0].Domain)
}

func TestListVerifiedDomainsForNode(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	user := db.CreateUserForTest("test")
	node := db.CreateNodeForTest(user, "testnode")

	_, err = db.CreateDomain(types.Domain{
		Domain: "unverified.example.com",
		NodeID: &node.ID,
	})
	require.NoError(t, err)

	_, err = db.CreateDomain(types.Domain{
		Domain:   "verified.example.com",
		NodeID:   &node.ID,
		Verified: true,
	})
	require.NoError(t, err)

	domains, err := db.ListVerifiedDomainsForNode(node.ID)
	require.NoError(t, err)
	assert.Len(t, domains, 1)
	assert.Equal(t, "verified.example.com", domains[0].Domain)
}

func TestDeleteDomainZoneWithChildren(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	user := db.CreateUserForTest("test")
	node := db.CreateNodeForTest(user, "testnode")

	_, err = db.CreateDomain(types.Domain{
		Domain:   "example.com",
		Provider: strp("cloudflare"),
		APIToken: strp("token"),
	})
	require.NoError(t, err)

	_, err = db.CreateDomain(types.Domain{
		Domain: "app.example.com",
		NodeID: &node.ID,
	})
	require.NoError(t, err)

	err = db.DeleteDomain("example.com")
	assert.ErrorIs(t, err, ErrZoneHasChildren)

	err = db.DeleteDomain("app.example.com")
	require.NoError(t, err)

	err = db.DeleteDomain("example.com")
	require.NoError(t, err)
}

func TestReassignDomain(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	user := db.CreateUserForTest("test")
	node1 := db.CreateNodeForTest(user, "node1")
	node2 := db.CreateNodeForTest(user, "node2")

	_, err = db.CreateDomain(types.Domain{
		Domain:   "move.example.com",
		NodeID:   &node1.ID,
		Verified: true,
	})
	require.NoError(t, err)

	domain, err := db.ReassignDomain("move.example.com", node2.ID)
	require.NoError(t, err)
	assert.Equal(t, node2.ID, *domain.NodeID)
	assert.True(t, domain.Verified)
}

func TestSetDomainVerified(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	user := db.CreateUserForTest("test")
	node := db.CreateNodeForTest(user, "testnode")

	_, err = db.CreateDomain(types.Domain{
		Domain: "verify.example.com",
		NodeID: &node.ID,
	})
	require.NoError(t, err)

	domain, err := db.SetDomainVerified("verify.example.com")
	require.NoError(t, err)
	assert.True(t, domain.Verified)
}

func TestFindParentZone(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	_, err = db.CreateDomain(types.Domain{
		Domain:   "example.com",
		Provider: strp("cloudflare"),
		APIToken: strp("token"),
	})
	require.NoError(t, err)

	zone, err := db.FindParentZone("app.example.com")
	require.NoError(t, err)
	require.NotNil(t, zone)
	assert.Equal(t, "example.com", zone.Domain)

	zone, err = db.FindParentZone("deep.sub.example.com")
	require.NoError(t, err)
	require.NotNil(t, zone)
	assert.Equal(t, "example.com", zone.Domain)

	zone, err = db.FindParentZone("other.dev")
	require.NoError(t, err)
	assert.Nil(t, zone)
}

func TestRegisterDomainAutoVerifyWithParentZone(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	user := db.CreateUserForTest("test")
	node := db.CreateNodeForTest(user, "desktop")

	// Create parent zone
	_, err = db.CreateDomain(types.Domain{
		Domain:   "bentley.sh",
		Provider: strp("cloudflare"),
		APIToken: strp("token"),
	})
	require.NoError(t, err)

	// Register subdomain under zone
	domain, err := db.CreateDomain(types.Domain{
		Domain: "bw.bentley.sh",
		NodeID: &node.ID,
	})
	require.NoError(t, err)
	assert.False(t, domain.Verified) // DB layer doesn't auto-verify

	// Check that parent zone is found
	zone, err := db.FindParentZone("bw.bentley.sh")
	require.NoError(t, err)
	require.NotNil(t, zone)
	assert.Equal(t, "bentley.sh", zone.Domain)

	// State layer would now call SetDomainVerified since zone exists
	verified, err := db.SetDomainVerified("bw.bentley.sh")
	require.NoError(t, err)
	assert.True(t, verified.Verified)

	// State layer would auto-grant owner access
	err = db.CreateDomainAccess(domain.ID, user.ID, "owner")
	require.NoError(t, err)

	// Verify domain shows up in verified list for node
	domains, err := db.ListVerifiedDomainsForNode(node.ID)
	require.NoError(t, err)
	assert.Len(t, domains, 1)
	assert.Equal(t, "bw.bentley.sh", domains[0].Domain)

	// Verify domain shows up in user-filtered list
	userDomains, err := db.ListDomains(nil, &user.ID)
	require.NoError(t, err)
	assert.Len(t, userDomains, 1)
}

func TestRegisterDomainWithCredentialsAutoVerify(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	user := db.CreateUserForTest("test")
	node := db.CreateNodeForTest(user, "server")

	// Register domain with credentials (zone + domain in one shot)
	_, err = db.CreateDomain(types.Domain{
		Domain:   "newdomain.dev",
		NodeID:   &node.ID,
		Provider: strp("cloudflare"),
		APIToken: strp("cf-token"),
	})
	require.NoError(t, err)

	// State layer would auto-verify since credentials provided
	verified, err := db.SetDomainVerified("newdomain.dev")
	require.NoError(t, err)
	assert.True(t, verified.Verified)
	assert.True(t, verified.IsZone()) // Has credentials
	assert.Equal(t, node.ID, *verified.NodeID) // Bound to node
}

func TestRegisterDomainPendingVerification(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	user := db.CreateUserForTest("test")
	node := db.CreateNodeForTest(user, "server")

	// Register domain with no credentials and no parent zone
	domain, err := db.CreateDomain(types.Domain{
		Domain: "external.dev",
		NodeID: &node.ID,
	})
	require.NoError(t, err)

	// No parent zone
	zone, err := db.FindParentZone("external.dev")
	require.NoError(t, err)
	assert.Nil(t, zone)

	// Should remain unverified with a verify token
	assert.False(t, domain.Verified)
	assert.NotNil(t, domain.VerifyToken)
	assert.Contains(t, *domain.VerifyToken, "hs-verify=")

	// Should NOT appear in verified domains list
	domains, err := db.ListVerifiedDomainsForNode(node.ID)
	require.NoError(t, err)
	assert.Len(t, domains, 0)
}

func TestDomainAccess(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	user := db.CreateUserForTest("accessuser")

	domain, err := db.CreateDomain(types.Domain{
		Domain:   "access.example.com",
		Provider: strp("cloudflare"),
		APIToken: strp("token"),
	})
	require.NoError(t, err)

	err = db.CreateDomainAccess(domain.ID, user.ID, "owner")
	require.NoError(t, err)

	domains, err := db.ListDomains(nil, &user.ID)
	require.NoError(t, err)
	assert.Len(t, domains, 1)
	assert.Equal(t, "access.example.com", domains[0].Domain)

	err = db.DeleteDomainAccess(domain.ID, user.ID)
	require.NoError(t, err)

	domains, err = db.ListDomains(nil, &user.ID)
	require.NoError(t, err)
	assert.Len(t, domains, 0)
}
