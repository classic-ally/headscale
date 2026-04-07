package cli

import (
	"context"
	"fmt"
	"strconv"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(domainCmd)

	domainCmd.AddCommand(addDomainCmd)
	addDomainCmd.Flags().StringP("node", "n", "", "Node name to bind domain to")
	addDomainCmd.Flags().StringP("provider", "p", "", "DNS provider (e.g., cloudflare)")
	addDomainCmd.Flags().StringP("api-token", "t", "", "DNS provider API token")

	domainCmd.AddCommand(removeDomainCmd)
	domainCmd.AddCommand(verifyDomainCmd)

	domainCmd.AddCommand(reassignDomainCmd)
	reassignDomainCmd.Flags().StringP("node", "n", "", "New node name")
	mustMarkRequired(reassignDomainCmd, "node")

	domainCmd.AddCommand(listDomainsCmd)
	listDomainsCmd.Flags().StringP("node", "n", "", "Filter by node name")
	listDomainsCmd.Flags().Uint64P("user-id", "u", 0, "Filter by user ID")

	domainCmd.AddCommand(setAccessCmd)
	setAccessCmd.Flags().Uint64P("user-id", "u", 0, "User ID")
	setAccessCmd.Flags().StringP("role", "r", "user", "Access role (owner or user)")
	mustMarkRequired(setAccessCmd, "user-id")

	domainCmd.AddCommand(removeAccessCmd)
	removeAccessCmd.Flags().Uint64P("user-id", "u", 0, "User ID")
	mustMarkRequired(removeAccessCmd, "user-id")
}

var domainCmd = &cobra.Command{
	Use:     "domains",
	Short:   "Manage domains for funnel/serve",
	Aliases: []string{"domain"},
}

var addDomainCmd = &cobra.Command{
	Use:   "add DOMAIN",
	Short: "Register a domain (zone with --provider, or subdomain with --node)",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errMissingParameter
		}
		return nil
	},
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		request := &v1.RegisterDomainRequest{
			Domain: args[0],
		}

		if node, _ := cmd.Flags().GetString("node"); node != "" {
			nodeID, err := resolveNodeName(ctx, client, node)
			if err != nil {
				return err
			}
			request.NodeId = nodeID
		}

		if provider, _ := cmd.Flags().GetString("provider"); provider != "" {
			request.Provider = provider
		}
		if apiToken, _ := cmd.Flags().GetString("api-token"); apiToken != "" {
			request.ApiToken = apiToken
		}

		response, err := client.RegisterDomain(ctx, request)
		if err != nil {
			return fmt.Errorf("registering domain: %w", err)
		}

		d := response.GetDomain()
		msg := "Domain registered"
		if d.GetVerified() {
			msg = "Domain registered and verified"
		} else if d.GetVerifyToken() != "" {
			msg = fmt.Sprintf("Domain registered (pending verification)\nAdd TXT record: _hs-verify.%s = %s",
				d.GetDomain(), d.GetVerifyToken())
		}

		return printOutput(cmd, d, msg)
	}),
}

var removeDomainCmd = &cobra.Command{
	Use:     "remove DOMAIN",
	Short:   "Remove a domain",
	Aliases: []string{"rm", "delete"},
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errMissingParameter
		}
		return nil
	},
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		response, err := client.DeleteDomain(ctx, &v1.DeleteDomainRequest{Domain: args[0]})
		if err != nil {
			return fmt.Errorf("deleting domain: %w", err)
		}
		return printOutput(cmd, response, "Domain deleted")
	}),
}

var verifyDomainCmd = &cobra.Command{
	Use:   "verify DOMAIN",
	Short: "Verify domain ownership via DNS TXT record",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errMissingParameter
		}
		return nil
	},
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		response, err := client.VerifyDomain(ctx, &v1.VerifyDomainRequest{Domain: args[0]})
		if err != nil {
			return fmt.Errorf("verifying domain: %w", err)
		}
		return printOutput(cmd, response.GetDomain(), "Domain verified")
	}),
}

var reassignDomainCmd = &cobra.Command{
	Use:   "reassign DOMAIN --node NAME",
	Short: "Reassign a domain to a different node",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errMissingParameter
		}
		return nil
	},
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		node, _ := cmd.Flags().GetString("node")
		nodeID, err := resolveNodeName(ctx, client, node)
		if err != nil {
			return err
		}

		response, err := client.ReassignDomain(ctx, &v1.ReassignDomainRequest{
			Domain: args[0],
			NodeId: nodeID,
		})
		if err != nil {
			return fmt.Errorf("reassigning domain: %w", err)
		}
		return printOutput(cmd, response.GetDomain(), "Domain reassigned")
	}),
}

var listDomainsCmd = &cobra.Command{
	Use:     "list",
	Short:   "List domains",
	Aliases: []string{"ls"},
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		request := &v1.ListDomainsRequest{}

		if node, _ := cmd.Flags().GetString("node"); node != "" {
			nodeID, err := resolveNodeName(ctx, client, node)
			if err != nil {
				return err
			}
			request.NodeId = nodeID
		}
		if userID, _ := cmd.Flags().GetUint64("user-id"); userID != 0 {
			request.UserId = userID
		}

		response, err := client.ListDomains(ctx, request)
		if err != nil {
			return fmt.Errorf("listing domains: %w", err)
		}

		return printListOutput(cmd, response.GetDomains(), func() error {
			tableData := pterm.TableData{{"ID", "DOMAIN", "NODE", "PROVIDER", "VERIFIED", "CREATED"}}
			for _, d := range response.GetDomains() {
				nodeStr := ""
				if d.GetNodeId() != 0 {
					nodeStr = strconv.FormatUint(d.GetNodeId(), util.Base10)
				}
				providerStr := ""
				if d.GetProvider() != "" {
					providerStr = d.GetProvider()
				}
				verifiedStr := "no"
				if d.GetVerified() {
					verifiedStr = "yes"
				}
				tableData = append(tableData, []string{
					strconv.FormatUint(d.GetId(), util.Base10),
					d.GetDomain(),
					nodeStr,
					providerStr,
					verifiedStr,
					d.GetCreatedAt().AsTime().Format(HeadscaleDateTimeFormat),
				})
			}
			return pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()
		})
	}),
}

var setAccessCmd = &cobra.Command{
	Use:   "set-access DOMAIN --user-id ID --role ROLE",
	Short: "Grant or update domain access for a user",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errMissingParameter
		}
		return nil
	},
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		userID, _ := cmd.Flags().GetUint64("user-id")
		role, _ := cmd.Flags().GetString("role")

		_, err := client.SetDomainAccess(ctx, &v1.SetDomainAccessRequest{
			Domain: args[0],
			UserId: userID,
			Role:   role,
		})
		if err != nil {
			return fmt.Errorf("setting domain access: %w", err)
		}
		return printOutput(cmd, map[string]string{"result": "access granted"}, "Domain access set")
	}),
}

var removeAccessCmd = &cobra.Command{
	Use:   "remove-access DOMAIN --user-id ID",
	Short: "Revoke domain access for a user",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errMissingParameter
		}
		return nil
	},
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		userID, _ := cmd.Flags().GetUint64("user-id")

		_, err := client.DeleteDomainAccess(ctx, &v1.DeleteDomainAccessRequest{
			Domain: args[0],
			UserId: userID,
		})
		if err != nil {
			return fmt.Errorf("deleting domain access: %w", err)
		}
		return printOutput(cmd, map[string]string{"result": "access revoked"}, "Domain access removed")
	}),
}

// resolveNodeName looks up a node by hostname and returns its ID.
func resolveNodeName(ctx context.Context, client v1.HeadscaleServiceClient, name string) (uint64, error) {
	nodes, err := client.ListNodes(ctx, &v1.ListNodesRequest{})
	if err != nil {
		return 0, fmt.Errorf("listing nodes: %w", err)
	}

	for _, node := range nodes.GetNodes() {
		if node.GetGivenName() == name || node.GetName() == name {
			return node.GetId(), nil
		}
	}

	return 0, fmt.Errorf("node not found: %s", name)
}
