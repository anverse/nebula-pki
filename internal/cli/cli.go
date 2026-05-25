// Package cli wires the cobra command tree.
package cli

import (
	"fmt"
	"io"

	"github.com/anverse/nebula-pki/internal/buildinfo"
	"github.com/anverse/nebula-pki/internal/config"
	"github.com/spf13/cobra"
)

// defaultConfigPath is consulted when -c/--config is not supplied.
const defaultConfigPath = "nebula.hcl"

// New builds the root command. stdout/stderr are injected to make the
// command tree testable; ldflag-injected version info is read from
// internal/buildinfo at call time.
func New(stdout, stderr io.Writer) *cobra.Command {
	var (
		showVersion bool
		configPath  string
	)

	root := &cobra.Command{
		Use:           "nebula-pki",
		Short:         "Declarative wrapper around nebula-cert",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if showVersion {
				fmt.Fprintln(cmd.OutOrStdout(), buildinfo.String())
				return nil
			}
			return cmd.Help()
		},
	}

	root.SetOut(stdout)
	root.SetErr(stderr)
	root.PersistentFlags().BoolVar(&showVersion, "version", false, "print version and exit")
	root.PersistentFlags().StringVarP(&configPath, "config", "c", defaultConfigPath, "path to HCL configuration file")

	root.AddCommand(newVersionCmd())
	root.AddCommand(newCheckCmd(&configPath))

	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), buildinfo.String())
			return nil
		},
	}
}

// newCheckCmd builds the `check` subcommand: parse + validate the HCL
// configuration without touching the output tree.
//
// The configPath pointer is owned by the root command's persistent
// flag; we read it through a pointer so flag parsing has run by the
// time the RunE executes.
func newCheckCmd(configPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "check",
		Short: "Parse and validate the HCL configuration",
		Long: "Parse the HCL configuration at -c/--config and run every validation rule.\n" +
			"No filesystem I/O is performed against the output tree.\n" +
			"Exits 0 on success, 1 on any parse or validation error.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(*configPath)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"ok: %s (ca mode=%s, hosts=%d)\n",
				cfg.Path, cfg.CA.Mode, len(cfg.Hosts),
			)
			return nil
		},
	}
}
