package hscontrol

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
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

// UpdateRoutes regenerates the funnel routes configuration file based on current node state.
// This is idempotent - it will only write and reload nginx if the configuration has changed.
func (fm *FunnelManager) UpdateRoutes() error {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	// Get all nodes from state
	nodes, err := fm.state.ListNodes()
	if err != nil {
		return fmt.Errorf("failed to list nodes: %w", err)
	}

	// Build routes configuration
	var buf bytes.Buffer
	buf.WriteString("# Auto-generated funnel routes - DO NOT EDIT MANUALLY\n")
	buf.WriteString("# Managed by headscale\n\n")

	routeCount := 0
	for _, node := range nodes {
		// Check if node has funnel enabled
		if node.Hostinfo == nil || !node.Hostinfo.IngressEnabled {
			continue
		}

		// Get node's FQDN
		fqdn, err := node.GetFQDN(fm.cfg.BaseDomain)
		if err != nil {
			log.Warn().
				Err(err).
				Str("node", node.Hostname).
				Msg("Failed to get FQDN for funnel-enabled node")
			continue
		}

		// Get node's primary IP address
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

		// Write route entry
		buf.WriteString(fmt.Sprintf("%s  %s:443;  # %s\n", fqdn, nodeIP, node.Hostname))
		routeCount++
	}

	content := buf.Bytes()

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

	fm.lastHash = currentHash

	log.Info().
		Int("routes", routeCount).
		Str("file", fm.routesFile).
		Msg("Updated funnel routes configuration")

	// Reload nginx
	if err := fm.reloadNginx(); err != nil {
		log.Error().
			Err(err).
			Msg("Failed to reload nginx after updating funnel routes")
		return fmt.Errorf("failed to reload nginx: %w", err)
	}

	return nil
}

// reloadNginx sends a reload signal to nginx via sudo systemctl.
// Requires sudo rule: headscale ALL=(ALL) NOPASSWD: /path/to/systemctl reload nginx
func (fm *FunnelManager) reloadNginx() error {
	// Use absolute paths for NixOS
	cmd := exec.Command("/run/wrappers/bin/sudo", "/run/current-system/sw/bin/systemctl", "reload", "nginx")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nginx reload failed: %w, output: %s", err, output)
	}

	log.Info().Msg("Nginx reloaded successfully")
	return nil
}
