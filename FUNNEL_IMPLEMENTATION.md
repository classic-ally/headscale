# Tailscale Funnel Implementation for Headscale

## Overview

This document describes the implementation of Tailscale Funnel support in headscale with a custom twist: instead of routing through Tailscale's infrastructure, funnel commands trigger automatic SNI routing through our own VPS.

## Goal

Enable the `tailscale funnel` UX while routing public internet traffic through our own SNI router on the VPS, not Tailscale's servers.

**User Experience:**
```bash
# On mesh node
tailscale cert desktop.icefox.xyz      # Get certificate via DNS-01 challenge
tailscale funnel 443                    # Signal: expose this service publicly
# → Headscale automatically adds SNI route on VPS
# → Public internet can now reach desktop.icefox.xyz → VPS → mesh node

tailscale funnel off                    # Remove from public internet
# → Headscale removes SNI route
```

## Architecture

```
Internet → VPS:443 (SNI Router) → Tailscale Mesh → Node:443
                ↑
                └─ Configured automatically when funnel is enabled
```

**vs. Tailscale Funnel:**
```
Internet → Tailscale Servers → Tailscale Mesh → Node:443
                ↑
                └─ Tailscale's infrastructure (we don't use this)
```

## Implementation Phases

### Phase 1: Enable Funnel Capability ✅ COMPLETED

**Goal:** Allow clients to run `tailscale funnel` without error.

**Code Changes:**
- **File:** `hscontrol/mapper/tail.go`
- **Change:** Add funnel capability to CapMap when certificates are enabled

```go
if cfg.CertificatesFeatureConfig.Enabled {
    tNode.CapMap[tailcfg.CapabilityHTTPS] = []tailcfg.RawMessage{}
    // Enable funnel capability - allows nodes to expose services via SNI router
    tNode.CapMap["https://tailscale.com/cap/funnel"] = []tailcfg.RawMessage{json.RawMessage(`["443"]`)}
}
```

**What this does:**
- Advertises to ALL nodes: "you can use funnel on port 443"
- Allows `tailscale funnel 443` command to work
- Does NOT automatically expose services (that's Phase 2)

**Limitations:**
- Global capability (all nodes can attempt funnel)
- Per-node ACL control would require full nodeAttrs implementation (4-6 days)
- For now, we accept this - actual exposure requires user action

### Phase 2: Detect Funnel State & Auto-Configure SNI Router ✅ COMPLETED

**Goal:** Detect when nodes enable/disable funnel and automatically update nginx SNI routes.

**Detection Method:**
When clients run `tailscale funnel`, they send `Hostinfo.IngressEnabled = true` in their map requests. This happens immediately (not on next poll - the client sends a new MapRequest right away).

**Implementation Approach: Stateless & Idempotent**

Instead of storing funnel state in a custom database column, we use the existing `Hostinfo` field (already persisted as JSON in the database). This avoids schema changes and makes upstream merging easier.

**Files Created/Modified:**

1. **`hscontrol/funnel.go`** - New FunnelManager component:
   - Queries all nodes from state
   - Filters for nodes with `Hostinfo.IngressEnabled == true`
   - Generates complete `/var/lib/headscale/funnel-routes.conf` file
   - Atomic write (temp file + rename)
   - Only reloads nginx if content changed (hash comparison)
   - Idempotent - safe to call repeatedly

2. **`hscontrol/types/config.go`** - Added configuration:
   ```go
   FunnelRoutesFile string  // Path to funnel routes config file
   ```

3. **`hscontrol/app.go`** - Wire FunnelManager into Headscale app:
   - Added `funnelManager *FunnelManager` field
   - Initialize in `NewHeadscale()`

4. **`hscontrol/poll.go`** - Trigger updates on MapRequest:
   ```go
   // After UpdateNodeFromMapRequest
   if err := m.h.funnelManager.UpdateRoutes(); err != nil {
       log.Error().Err(err).Msg("Failed to update funnel routes")
       // Don't fail the request, just log
   }
   ```

**NixOS Configuration Changes:**

1. **`services/sni-router.nix`** - Add dynamic routes include:
   ```nginx
   map $ssl_preread_server_name $backend {
     # Static routes from NixOS config
     ctrl.bentley.sh  127.0.0.1:8443;

     # Dynamic funnel routes (auto-managed by headscale)
     include /var/lib/headscale/funnel-routes.conf;

     default 127.0.0.1:8444;
   }
   ```

2. **`services/headscale.nix`** - Add sudo rule for nginx reload:
   ```nix
   security.sudo.extraRules = [{
     users = [ "headscale" ];
     commands = [{
       command = "${pkgs.systemd}/bin/systemctl reload nginx";
       options = [ "NOPASSWD" ];
     }];
   }];
   ```

**How It Works:**

1. User runs `tailscale funnel 443` on a mesh node
2. Client immediately sends MapRequest with `Hostinfo.IngressEnabled = true`
3. Headscale processes MapRequest in `poll.go`
4. FunnelManager queries all nodes, finds funnel-enabled ones
5. Generates routes file: `desktop.icefox.xyz  100.64.0.2:443;`
6. If changed: atomic write + `sudo systemctl reload nginx`
7. Nginx gracefully reloads with new routes
8. Public traffic can now reach `https://desktop.icefox.xyz`

**Benefits of Stateless Approach:**

- No database schema changes - easier upstream merging
- Self-healing on restart (next MapRequest restores state)
- Idempotent - can safely call UpdateRoutes() multiple times
- `Hostinfo` already persisted in database as JSON
- Simple, predictable behavior

## Certificate Provisioning (Already Working ✅)

The `tailscale cert` command already works via:

1. Client requests cert from headscale
2. Headscale calls `/var/lib/headscale/set-dns-cloudflare` script
3. Script creates TXT record via Cloudflare API
4. Script waits for DNS propagation (polls multiple DNS servers)
5. ACME challenge completes
6. Client receives certificate

**Key Implementation:**
- `services/headscale.nix` - Cloudflare DNS script
- `hscontrol/noise.go` - SetDNSHandler endpoint

## Current Status

### ✅ Completed
- Certificate provisioning (`tailscale cert`)
- DNS-01 ACME challenges via Cloudflare
- DNS propagation detection
- SNI router with dynamic routes support
- **Phase 1**: Funnel capability advertisement
- **Phase 2**: Funnel state detection & automatic SNI router updates

### 📋 Next Steps
- Commit and push headscale changes
- Commit and push nix-config changes
- Build and deploy to VPS (asgard)
- Test Phase 1 & 2 together

## Testing Plan

### Phase 1 Testing (After Deploy)
```bash
# On VPS after deploying new headscale
tailscale debug netmap | jq '.SelfNode.CapMap'
# Expected: "https://tailscale.com/cap/funnel": ["443"]

tailscale funnel 443
# Expected: No "funnel node attribute not set" error
# May show other errors (no server running, etc.) - that's OK
```

### Phase 2 Testing (End-to-End)
```bash
# Terminal 1: Watch headscale logs
journalctl -u headscale.service -f

# Terminal 2: Start a web server on a mesh node
python3 -m http.server 443

# Terminal 2: Enable funnel
tailscale funnel 443

# Expected in logs (Terminal 1):
# "Updated funnel routes configuration" routes=1
# "Nginx reloaded successfully"

# Check generated routes file on VPS
cat /var/lib/headscale/funnel-routes.conf
# Expected: Contains route like "nodename.icefox.xyz  100.64.x.x:443;"

# Terminal 3: From internet (not on tailnet) - test public access
curl https://nodename.icefox.xyz
# Expected: Should reach the python server!

# Terminal 2: Disable funnel
tailscale funnel off

# Expected in logs (Terminal 1):
# "Updated funnel routes configuration" routes=0
# "Nginx reloaded successfully"

# Terminal 3: From internet - verify funnel disabled
curl https://nodename.icefox.xyz
# Expected: Connection refused or timeout
```

## Design Decisions

### Why Not Full NodeAttrs Implementation?
**Pros of nodeAttrs:**
- Proper ACL-based funnel permission control
- Tailscale-compatible policy syntax
- Foundation for future features

**Cons:**
- 4-6 days implementation effort
- Complex policy parsing and resolution
- Overkill for single-user/small team use case

**Decision:** Use global funnel capability for MVP. Can add nodeAttrs later if multi-user ACL control is needed.

### Why Not Use Tailscale's Funnel Infrastructure?
We control our own VPS and want:
- Full control over ingress
- Custom domains (bentley.sh, icefox.xyz)
- No dependency on Tailscale's availability
- Ability to customize routing logic

### Port Restrictions
Currently hardcoded to port 443 in the capability:
```go
json.RawMessage(`["443"]`)
```

**Rationale:**
- Most web services use 443
- Avoids port conflicts
- Simplifies SNI routing (all traffic on 443)

**Future:** Could allow multiple ports if needed:
```go
json.RawMessage(`["443", "8443"]`)
```

## Related Files

### Headscale (Custom Build)
- `hscontrol/mapper/tail.go` - Capability advertisement
- `hscontrol/noise.go` - SetDNS handler (certificates)
- `hscontrol/poll.go` - Map request handling (TODO: funnel detection)
- `hscontrol/types/node.go` - Node data structures (TODO: funnel field)

### NixOS Configuration
- `services/headscale.nix` - Headscale service + cert automation
- `services/sni-router.nix` - Nginx SNI routing
- `hosts/asgard/configuration.nix` - VPS-specific config
- `modules/nix-core.nix` - Nix settings (trusted-users)

## References

- [Tailscale Funnel Docs](https://tailscale.com/kb/1223/funnel)
- [Headscale Issue #1040](https://github.com/juanfont/headscale/issues/1040) - Funnel support request
- [Tailscale ACL NodeAttrs](https://tailscale.com/kb/1337/acl-syntax#nodeattrs)
- Original headscale fork: `https://github.com/nom3ad/headscale/tree/feature/tailscale-serve`

## Estimated Complexity

| Phase | Description | Complexity | Time Estimate |
|-------|-------------|------------|---------------|
| Phase 1 | Funnel capability | ⭐ Simple | 5 minutes (Done) |
| Phase 2 | Detect funnel state | ⭐⭐ Moderate | 2-3 hours |
| Phase 3 | Auto SNI routing | ⭐⭐⭐ Moderate | 3-4 hours |
| **Total** | **MVP Funnel** | | **~5-7 hours** |
| Future | Full nodeAttrs | ⭐⭐⭐⭐ Complex | 4-6 days |

## Next Steps

1. ✅ Complete remote builder setup
2. ✅ Build headscale with funnel capability
3. 🔄 Deploy to VPS and test Phase 1
4. 📋 Implement Phase 2 (funnel state detection)
5. 📋 Implement Phase 3 (SNI automation)
6. 📋 End-to-end testing
7. 📋 Document user workflow
