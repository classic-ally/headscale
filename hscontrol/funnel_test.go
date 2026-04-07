package hscontrol

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/tailcfg"
	tsptr "tailscale.com/types/ptr"
)

func TestGenerateFunnelRoutes(t *testing.T) {
	tests := []struct {
		name          string
		nodes         types.Nodes
		extraRecords  []tailcfg.DNSRecord
		baseDomain    string
		wantContains  []string
		wantAbsent    []string
		wantEmptyBody bool
	}{
		{
			name:          "no-nodes",
			nodes:         types.Nodes{},
			baseDomain:    "icefox.xyz",
			wantEmptyBody: true,
		},
		{
			name: "node-without-funnel",
			nodes: types.Nodes{
				{
					GivenName: "desktop",
					Hostname:  "desktop",
					UserID:    tsptr.To(uint(1)),
					User:      &types.User{Name: "alice"},
					IPv4:      tsptr.To(netip.MustParseAddr("100.64.0.6")),
					Hostinfo:  &tailcfg.Hostinfo{IngressEnabled: false},
				},
			},
			baseDomain:    "icefox.xyz",
			wantEmptyBody: true,
		},
		{
			name: "node-with-funnel-magicdns-only",
			nodes: types.Nodes{
				{
					GivenName: "desktop",
					Hostname:  "desktop",
					UserID:    tsptr.To(uint(1)),
					User:      &types.User{Name: "alice"},
					IPv4:      tsptr.To(netip.MustParseAddr("100.64.0.6")),
					Hostinfo:  &tailcfg.Hostinfo{IngressEnabled: true},
				},
			},
			baseDomain: "icefox.xyz",
			wantContains: []string{
				"desktop.icefox.xyz  100.64.0.6:443;  # desktop",
			},
		},
		{
			name: "node-with-funnel-and-extra-records",
			nodes: types.Nodes{
				{
					GivenName: "desktop",
					Hostname:  "desktop",
					UserID:    tsptr.To(uint(1)),
					User:      &types.User{Name: "alice"},
					IPv4:      tsptr.To(netip.MustParseAddr("100.64.0.6")),
					Hostinfo:  &tailcfg.Hostinfo{IngressEnabled: true},
				},
			},
			baseDomain: "icefox.xyz",
			extraRecords: []tailcfg.DNSRecord{
				{Name: "bw.bentley.sh.", Type: "A", Value: "100.64.0.6"},
				{Name: "wolfson.bar.", Type: "A", Value: "100.64.0.6"},
			},
			wantContains: []string{
				"desktop.icefox.xyz  100.64.0.6:443;  # desktop",
				"bw.bentley.sh  100.64.0.6:443;  # desktop",
				"wolfson.bar  100.64.0.6:443;  # desktop",
			},
		},
		{
			name: "mixed-funnel-and-non-funnel-nodes",
			nodes: types.Nodes{
				{
					GivenName: "desktop",
					Hostname:  "desktop",
					UserID:    tsptr.To(uint(1)),
					User:      &types.User{Name: "alice"},
					IPv4:      tsptr.To(netip.MustParseAddr("100.64.0.6")),
					Hostinfo:  &tailcfg.Hostinfo{IngressEnabled: true},
				},
				{
					GivenName: "laptop",
					Hostname:  "laptop",
					UserID:    tsptr.To(uint(1)),
					User:      &types.User{Name: "alice"},
					IPv4:      tsptr.To(netip.MustParseAddr("100.64.0.7")),
					Hostinfo:  &tailcfg.Hostinfo{IngressEnabled: false},
				},
			},
			baseDomain: "icefox.xyz",
			wantContains: []string{
				"desktop.icefox.xyz  100.64.0.6:443;  # desktop",
			},
			wantAbsent: []string{
				"laptop",
			},
		},
		{
			name: "node-with-nil-hostinfo",
			nodes: types.Nodes{
				{
					GivenName: "ghost",
					Hostname:  "ghost",
					UserID:    tsptr.To(uint(1)),
					User:      &types.User{Name: "alice"},
					IPv4:      tsptr.To(netip.MustParseAddr("100.64.0.8")),
					Hostinfo:  nil,
				},
			},
			baseDomain:    "icefox.xyz",
			wantEmptyBody: true,
		},
		{
			name: "funnel-node-no-ip",
			nodes: types.Nodes{
				{
					GivenName: "noip",
					Hostname:  "noip",
					UserID:    tsptr.To(uint(1)),
					User:      &types.User{Name: "alice"},
					Hostinfo:  &tailcfg.Hostinfo{IngressEnabled: true},
				},
			},
			baseDomain:    "icefox.xyz",
			wantEmptyBody: true,
		},
		{
			name: "multiple-funnel-nodes-different-domains",
			nodes: types.Nodes{
				{
					GivenName: "desktop",
					Hostname:  "desktop",
					UserID:    tsptr.To(uint(1)),
					User:      &types.User{Name: "alice"},
					IPv4:      tsptr.To(netip.MustParseAddr("100.64.0.6")),
					Hostinfo:  &tailcfg.Hostinfo{IngressEnabled: true},
				},
				{
					GivenName: "server",
					Hostname:  "server",
					UserID:    tsptr.To(uint(2)),
					User:      &types.User{Name: "bob"},
					IPv4:      tsptr.To(netip.MustParseAddr("100.64.0.10")),
					Hostinfo:  &tailcfg.Hostinfo{IngressEnabled: true},
				},
			},
			baseDomain: "icefox.xyz",
			extraRecords: []tailcfg.DNSRecord{
				{Name: "bw.bentley.sh.", Type: "A", Value: "100.64.0.6"},
				{Name: "app.bob.dev.", Type: "A", Value: "100.64.0.10"},
			},
			wantContains: []string{
				"desktop.icefox.xyz  100.64.0.6:443;  # desktop",
				"bw.bentley.sh  100.64.0.6:443;  # desktop",
				"server.icefox.xyz  100.64.0.10:443;  # server",
				"app.bob.dev  100.64.0.10:443;  # server",
			},
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

			got := string(GenerateFunnelRoutes(cfg, tt.nodes, nil))

			// Strip the header to check for "empty body"
			body := got
			for _, prefix := range []string{
				"# Auto-generated funnel routes - DO NOT EDIT MANUALLY\n",
				"# Managed by headscale\n",
				"\n",
			} {
				body = strings.TrimPrefix(body, prefix)
			}

			if tt.wantEmptyBody && body != "" {
				t.Errorf("expected empty body after header, got:\n%s", body)
			}

			for _, want := range tt.wantContains {
				if !strings.Contains(got, want) {
					t.Errorf("output missing expected line %q\ngot:\n%s", want, got)
				}
			}

			for _, absent := range tt.wantAbsent {
				if strings.Contains(got, absent) {
					t.Errorf("output should not contain %q\ngot:\n%s", absent, got)
				}
			}
		})
	}
}
