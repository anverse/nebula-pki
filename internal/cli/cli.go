// Package cli wires the cobra command tree.
package cli

import (
	"fmt"
	"io"
	"time"

	"github.com/anverse/nebula-pki/internal/apply"
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
			return runReconcile(cmd, configPath)
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

// runReconcile is the default action: load the configuration and bring the
// output tree in line with it. In v0.0.3 this reconciles the CA only; host
// blocks are parsed and counted but not yet signed.
func runReconcile(cmd *cobra.Command, configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	rep, err := apply.Reconcile(cfg, apply.Options{
		Now:              time.Now().UTC(),
		GeneratorVersion: buildinfo.Version,
	})
	if err != nil {
		return err
	}
	writeReconcileSummary(cmd.OutOrStdout(), rep)
	return nil
}

// writeReconcileSummary prints a short human summary of a reconcile run.
//
// The "host(s) parsed but not yet reconciled" note is printed only on
// runs that actually generated artifacts. On an idempotent rerun the
// hosts were already ignored on the first run; repeating the warning
// every subsequent invocation would be noise (and would fight the
// "byte-identical, zero-noise" idempotency guarantee from spec/adr/002,
// since an operator running the tool in CI on every commit would see it
// forever until v0.0.5 lands).
func writeReconcileSummary(w io.Writer, rep *apply.Report) {
	if rep.Changed {
		fmt.Fprintf(w, "generated CA %q\n", rep.CAName)
		fmt.Fprintf(w, "  cert: %s\n", rep.CACertPath)
		fmt.Fprintf(w, "  key:  %s\n", rep.CAKeyPath)
		fmt.Fprintf(w, "wrote manifest: %s\n", rep.ManifestPath)
		if rep.HostsParsed > 0 {
			fmt.Fprintf(w,
				"note: %d host(s) parsed but not yet reconciled (host signing lands in a later release)\n",
				rep.HostsParsed,
			)
		}
		return
	}
	fmt.Fprintln(w, "up to date; nothing to write")
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
