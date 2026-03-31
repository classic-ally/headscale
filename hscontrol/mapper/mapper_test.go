package mapper

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
)

var iap = func(ipStr string) *netip.Addr {
	ip := netip.MustParseAddr(ipStr)
	return &ip
}

func TestDNSConfigMapResponse(t *testing.T) {
	tests := []struct {
		magicDNS bool
		want     *tailcfg.DNSConfig
	}{
		{
			magicDNS: true,
			want: &tailcfg.DNSConfig{
				Routes: map[string][]*dnstype.Resolver{},
				Domains: []string{
					"foobar.headscale.net",
				},
				Proxied: true,
			},
		},
		{
			magicDNS: false,
			want: &tailcfg.DNSConfig{
				Domains: []string{"foobar.headscale.net"},
				Proxied: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("with-magicdns-%v", tt.magicDNS), func(t *testing.T) {
			mach := func(hostname, username string, userid uint) *types.Node {
				return &types.Node{
					Hostname: hostname,
					UserID:   new(userid),
					User: &types.User{
						Name: username,
					},
				}
			}

			baseDomain := "foobar.headscale.net"

			dnsConfigOrig := tailcfg.DNSConfig{
				Routes:  make(map[string][]*dnstype.Resolver),
				Domains: []string{baseDomain},
				Proxied: tt.magicDNS,
			}

			nodeInShared1 := mach("test_get_shared_nodes_1", "shared1", 1)

			got := generateDNSConfig(
				&types.Config{
					TailcfgDNSConfig: &dnsConfigOrig,
				},
				nodeInShared1.View(),
			)

			if diff := cmp.Diff(tt.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("expandAlias() unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

func uintp(v uint) *uint { return &v }

func TestGetCertDomainsForNode(t *testing.T) {
	tests := []struct {
		name         string
		node         *types.Node
		baseDomain   string
		extraRecords []tailcfg.DNSRecord
		want         []string
	}{
		{
			name: "magicdns-only",
			node: &types.Node{
				GivenName: "desktop",
				UserID:    uintp(1),
				User:      &types.User{Name: "alice"},
				IPv4:      iap("100.64.0.6"),
			},
			baseDomain: "icefox.xyz",
			want:       []string{"desktop.icefox.xyz"},
		},
		{
			name: "with-extra-records-matching-ipv4",
			node: &types.Node{
				GivenName: "desktop",
				UserID:    uintp(1),
				User:      &types.User{Name: "alice"},
				IPv4:      iap("100.64.0.6"),
			},
			baseDomain: "icefox.xyz",
			extraRecords: []tailcfg.DNSRecord{
				{Name: "bw.bentley.sh.", Type: "A", Value: "100.64.0.6"},
				{Name: "feed.bentley.sh.", Type: "A", Value: "100.64.0.6"},
			},
			want: []string{"desktop.icefox.xyz", "bw.bentley.sh", "feed.bentley.sh"},
		},
		{
			name: "extra-records-different-node",
			node: &types.Node{
				GivenName: "laptop",
				UserID:    uintp(1),
				User:      &types.User{Name: "alice"},
				IPv4:      iap("100.64.0.7"),
			},
			baseDomain: "icefox.xyz",
			extraRecords: []tailcfg.DNSRecord{
				{Name: "bw.bentley.sh.", Type: "A", Value: "100.64.0.6"},
			},
			want: []string{"laptop.icefox.xyz"},
		},
		{
			name: "strips-trailing-dot",
			node: &types.Node{
				GivenName: "desktop",
				UserID:    uintp(1),
				User:      &types.User{Name: "alice"},
				IPv4:      iap("100.64.0.6"),
			},
			baseDomain: "icefox.xyz",
			extraRecords: []tailcfg.DNSRecord{
				{Name: "wolfson.bar.", Type: "A", Value: "100.64.0.6"},
			},
			want: []string{"desktop.icefox.xyz", "wolfson.bar"},
		},
		{
			name: "ignores-non-address-records",
			node: &types.Node{
				GivenName: "desktop",
				UserID:    uintp(1),
				User:      &types.User{Name: "alice"},
				IPv4:      iap("100.64.0.6"),
			},
			baseDomain: "icefox.xyz",
			extraRecords: []tailcfg.DNSRecord{
				{Name: "bw.bentley.sh.", Type: "CNAME", Value: "desktop.icefox.xyz"},
				{Name: "real.bentley.sh.", Type: "A", Value: "100.64.0.6"},
			},
			want: []string{"desktop.icefox.xyz", "real.bentley.sh"},
		},
		{
			name: "no-base-domain",
			node: &types.Node{
				GivenName: "desktop",
				UserID:    uintp(1),
				User:      &types.User{Name: "alice"},
				IPv4:      iap("100.64.0.6"),
			},
			baseDomain: "",
			extraRecords: []tailcfg.DNSRecord{
				{Name: "bw.bentley.sh.", Type: "A", Value: "100.64.0.6"},
			},
			want: []string{"desktop", "bw.bentley.sh"},
		},
		{
			name: "nil-dns-config",
			node: &types.Node{
				GivenName: "desktop",
				UserID:    uintp(1),
				User:      &types.User{Name: "alice"},
				IPv4:      iap("100.64.0.6"),
			},
			baseDomain: "icefox.xyz",
			want:       []string{"desktop.icefox.xyz"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &types.Config{
				BaseDomain: tt.baseDomain,
			}
			if tt.extraRecords != nil {
				cfg.TailcfgDNSConfig = &tailcfg.DNSConfig{
					ExtraRecords: tt.extraRecords,
				}
			}

			got := GetCertDomainsForNode(cfg, tt.node)

			if diff := cmp.Diff(tt.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("GetCertDomainsForNode() unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGenerateDNSConfigIncludesCertDomains(t *testing.T) {
	node := &types.Node{
		GivenName: "desktop",
		UserID:    uintp(1),
		User:      &types.User{Name: "alice"},
		IPv4:      iap("100.64.0.6"),
	}

	dnsConfigOrig := tailcfg.DNSConfig{
		Routes:  make(map[string][]*dnstype.Resolver),
		Domains: []string{"icefox.xyz"},
		Proxied: true,
		ExtraRecords: []tailcfg.DNSRecord{
			{Name: "bw.bentley.sh.", Type: "A", Value: "100.64.0.6"},
		},
	}

	got := generateDNSConfig(
		&types.Config{
			BaseDomain:       "icefox.xyz",
			TailcfgDNSConfig: &dnsConfigOrig,
		},
		node.View(),
	)

	wantCertDomains := []string{"desktop.icefox.xyz", "bw.bentley.sh"}
	if diff := cmp.Diff(wantCertDomains, got.CertDomains, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("generateDNSConfig() CertDomains (-want +got):\n%s", diff)
	}
}
