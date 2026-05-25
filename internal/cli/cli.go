// Package cli wires the cobra command tree.
//
// v0.0.1 only exposes `nebula-pki version` (and the global `--version` flag).
// Subsequent versions add `check`, the default reconcile action, and `--dry-run`.
package cli

import (
	"fmt"
	"io"

	"github.com/anverse/nebula-pki/internal/buildinfo"
	"github.com/spf13/cobra"
)

// New builds the root command. stdout/stderr are injected to make the
// command tree testable; ldflag-injected version info is read from
// internal/buildinfo at call time.
func New(stdout, stderr io.Writer) *cobra.Command {
	var showVersion bool

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
			// v0.0.1: no reconcile yet. Print help and exit 0.
			return cmd.Help()
		},
	}

	root.SetOut(stdout)
	root.SetErr(stderr)
	root.PersistentFlags().BoolVar(&showVersion, "version", false, "print version and exit")

	root.AddCommand(newVersionCmd())

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
