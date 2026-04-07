package hscontrol

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/juanfont/headscale/hscontrol/mapper"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
	"tailscale.com/types/views"
)

// FunnelManager manages automatic SNI router configuration for nodes with funnel enabled.
type FunnelManager struct {
	state      *state.State
	cfg        *types.Config
	routesFile string
	mu         sync.Mutex
	lastHash   [32]byte
}

// NewFunnelManager creates a new FunnelManager instance.
func NewFunnelManager(state *state.State, cfg *types.Config) *FunnelManager {
	routesFile := "/var/lib/headscale/funnel-routes.conf"
	if cfg.FunnelRoutesFile != "" {
		routesFile = cfg.FunnelRoutesFile
	}

	fm := &FunnelManager{
		state:      state,
		cfg:        cfg,
		routesFile: routesFile,
	}

	// Initialize empty routes file if it doesn't exist
	// This prevents nginx from failing to start when it tries to include the file
	if err := fm.initializeRoutesFile(); err != nil {
		log.Warn().
			Err(err).
			Str("file", routesFile).
			Msg("Failed to initialize funnel routes file")
	}

	return fm
}

// initializeRoutesFile creates an empty routes file if it doesn't exist.
func (fm *FunnelManager) initializeRoutesFile() error {
	// Check if file exists
	if _, err := os.Stat(fm.routesFile); err == nil {
		return nil // File already exists
	}

	// Ensure directory exists
	dir := filepath.Dir(fm.routesFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Create empty file with proper permissions
	content := []byte("# Auto-generated funnel routes - DO NOT EDIT MANUALLY\n# Managed by headscale\n")
	if err := os.WriteFile(fm.routesFile, content, 0644); err != nil {
		return fmt.Errorf("failed to create routes file: %w", err)
	}

	log.Info().
		Str("file", fm.routesFile).
		Msg("Initialized empty funnel routes file")

	return nil
}

// GenerateFunnelRoutes builds the nginx SNI route configuration for funnel-enabled nodes.
// This is a pure function for testability. Pass nil for domainLookup to use config-only domains.
func GenerateFunnelRoutes(cfg *types.Config, nodes types.Nodes, domainLookup mapper.DomainLookup) []byte {
	var buf bytes.Buffer
	buf.WriteString("# Auto-generated funnel routes - DO NOT EDIT MANUALLY\n")
	buf.WriteString("# Managed by headscale\n\n")

	for _, node := range nodes {
		if node.Hostinfo == nil || !node.Hostinfo.IngressEnabled {
			continue
		}

		var nodeIP string
		if node.IPv4 != nil {
			nodeIP = node.IPv4.String()
		} else if node.IPv6 != nil {
			nodeIP = fmt.Sprintf("[%s]", node.IPv6.String())
		} else {
			log.Warn().
				Str("node", node.Hostname).
				Msg("Funnel-enabled node has no IP address")
			continue
		}

		certDomains := mapper.GetCertDomainsForNode(cfg, node, domainLookup)

		for _, domain := range certDomains {
			buf.WriteString(fmt.Sprintf("%s  %s:443;  # %s\n", domain, nodeIP, node.Hostname))
		}
	}

	return buf.Bytes()
}

// generateFunnelRoutesFromViews builds routes from NodeView slice (used at runtime).
func generateFunnelRoutesFromViews(cfg *types.Config, nodes views.Slice[types.NodeView], domainLookup mapper.DomainLookup) []byte {
	var buf bytes.Buffer
	buf.WriteString("# Auto-generated funnel routes - DO NOT EDIT MANUALLY\n")
	buf.WriteString("# Managed by headscale\n\n")

	for i := range nodes.Len() {
		node := nodes.At(i)
		if !node.Hostinfo().Valid() || !node.Hostinfo().IngressEnabled() {
			continue
		}

		var nodeIP string
		if node.IPv4().Valid() {
			nodeIP = node.IPv4().Get().String()
		} else if node.IPv6().Valid() {
			nodeIP = fmt.Sprintf("[%s]", node.IPv6().Get().String())
		} else {
			log.Warn().
				Str("node", node.Hostname()).
				Msg("Funnel-enabled node has no IP address")
			continue
		}

		certDomains := mapper.GetCertDomainsForNodeView(cfg, node, domainLookup)

		for _, domain := range certDomains {
			buf.WriteString(fmt.Sprintf("%s  %s:443;  # %s\n", domain, nodeIP, node.Hostname()))
		}
	}

	return buf.Bytes()
}

// UpdateRoutes regenerates the funnel routes configuration file based on current node state.
// This is idempotent - it will only write and reload nginx if the configuration has changed.
func (fm *FunnelManager) UpdateRoutes() error {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	nodes := fm.state.ListNodes()

	content := generateFunnelRoutesFromViews(fm.cfg, nodes, fm.state.VerifiedDomainsForNode)

	// Check if content has changed
	currentHash := sha256.Sum256(content)
	if currentHash == fm.lastHash {
		log.Debug().Msg("Funnel routes unchanged, skipping update")
		return nil
	}

	// Ensure directory exists
	dir := filepath.Dir(fm.routesFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Atomic write: write to temp file, then rename
	tempFile := fm.routesFile + ".tmp"
	if err := os.WriteFile(tempFile, content, 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	if err := os.Rename(tempFile, fm.routesFile); err != nil {
		os.Remove(tempFile) // Clean up temp file
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	// Explicitly set permissions to ensure nginx can read it
	// This is necessary because the file may inherit restrictive permissions from the directory
	if err := os.Chmod(fm.routesFile, 0644); err != nil {
		log.Warn().Err(err).Msg("Failed to set permissions on funnel routes file")
	}

	fm.lastHash = currentHash

	log.Info().
		Int("routes", nodes.Len()).
		Str("file", fm.routesFile).
		Msg("Updated funnel routes configuration (nginx will auto-reload)")

	return nil
}
