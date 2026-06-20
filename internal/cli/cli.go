// Package cli wires the cobra command tree.
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/anverse/nebula-pki/internal/apply"
	"github.com/anverse/nebula-pki/internal/buildinfo"
	"github.com/anverse/nebula-pki/internal/config"
	"github.com/anverse/nebula-pki/internal/pki"
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
		dryRun      bool
	)

	root := &cobra.Command{
		Use:   "nebula-pki",
		Short: "Declarative PKI manager for Nebula mesh networks",
		Long: `nebula-pki reconciles the PKI for a Nebula mesh network.

On each run it reads nebula.hcl (or the path given by -c), generates or
loads the CA, signs any host certificates that are new or missing, and
records the result in a manifest. Runs are idempotent: an unchanged tree
writes nothing.

Progress is written to stderr. Use --dry-run to preview what would change
without touching the filesystem.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if showVersion {
				fmt.Fprintln(cmd.OutOrStdout(), buildinfo.String())
				return nil
			}
			return runReconcile(cmd, configPath, dryRun)
		},
	}

	root.SetOut(stdout)
	root.SetErr(stderr)
	root.PersistentFlags().BoolVar(&showVersion, "version", false, "print version and exit")
	root.PersistentFlags().StringVarP(&configPath, "config", "c", defaultConfigPath, "path to HCL configuration file")
	root.Flags().BoolVar(&dryRun, "dry-run", false, "preview planned writes without modifying the filesystem")

	root.AddCommand(newVersionCmd())
	root.AddCommand(newCheckCmd(&configPath))

	return root
}

// runReconcile is the default action: load the configuration and bring the
// output tree in line with it. It reconciles the CA in both generate and
// reference mode, and signs any host certificates that are new or missing.
// When dryRun is true the plan is previewed on stdout without any writes.
func runReconcile(cmd *cobra.Command, configPath string, dryRun bool) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	rep, err := apply.Reconcile(cfg, apply.Options{
		Now:              time.Now().UTC(),
		GeneratorVersion: buildinfo.Version,
		Warn:             cmd.ErrOrStderr(),
		DryRun:           dryRun,
		Out:              cmd.OutOrStdout(),
	})
	if err != nil {
		return err
	}
	if !dryRun {
		writeReconcileSummary(cmd.ErrOrStderr(), rep)
	}
	return nil
}

// writeReconcileSummary prints a short human summary of a reconcile run.
func writeReconcileSummary(w io.Writer, rep *apply.Report) {
	if !rep.Changed {
		fmt.Fprintln(w, "up to date; nothing to do")
		return
	}

	if rep.CAMode == "reference" {
		fmt.Fprintf(w, "using referenced CA %q\n", rep.CAName)
		fmt.Fprintf(w, "  cert: %s\n", rep.CACertPath)
		fmt.Fprintf(w, "  key:  %s\n", rep.CAKeyPath)
	} else {
		fmt.Fprintf(w, "generated CA %q\n", rep.CAName)
		fmt.Fprintf(w, "  cert: %s\n", rep.CACertPath)
		fmt.Fprintf(w, "  key:  %s\n", rep.CAKeyPath)
	}
	for _, h := range rep.SignedHosts {
		fmt.Fprintf(w, "signed host %q\n", h.Label)
		for _, a := range h.Artifacts {
			fmt.Fprintf(w, "  cert: %s\n", a.CertPath)
			fmt.Fprintf(w, "  key:  %s\n", a.KeyPath)
		}
	}
	if len(rep.StaleArtifacts) > 0 {
		fmt.Fprintln(w, "notice: the following files are no longer managed by this configuration.")
		fmt.Fprintln(w, "  They can be deleted once you have confirmed the new location is correct:")
		for _, p := range rep.StaleArtifacts {
			fmt.Fprintf(w, "  %s\n", p)
		}
	}
	fmt.Fprintf(w, "wrote manifest: %s\n", rep.ManifestPath)
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
// In reference mode it additionally reads the operator-supplied CA files
// (cert_file / key_file) and reports the CA fingerprint, so an operator
// can confirm `check` is pointed at the CA they expect. This read is the
// only filesystem access `check` performs, and it never writes anything.
//
// The configPath pointer is owned by the root command's persistent
// flag; we read it through a pointer so flag parsing has run by the
// time the RunE executes.
func newCheckCmd(configPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "check",
		Short: "Parse and validate the HCL configuration",
		Long: "Parse the HCL configuration at -c/--config and run every validation rule.\n" +
			"No output tree is written. In CA reference mode the referenced\n" +
			"cert_file/key_file are read and the CA fingerprint is reported.\n" +
			"Exits 0 on success, 1 on any parse or validation error.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(*configPath)
			if err != nil {
				return err
			}
			// This line reports that the *configuration* parsed and passed
			// every validation rule. In reference mode the referenced CA is
			// then read and verified separately; if that fails, the error
			// follows this line — which is still accurate, the config is
			// valid, the referenced files are the problem. Hence "config
			// valid" rather than a blanket "ok" that would read as "the
			// whole check passed" right before an error.
			fmt.Fprintf(cmd.OutOrStdout(),
				"config valid: %s (ca mode=%s, hosts=%d)\n",
				cfg.Path, cfg.CA.Mode, len(cfg.Hosts),
			)
			if cfg.CA.Mode == config.CAModeReference {
				return checkReferenceCA(cmd, cfg)
			}
			return nil
		},
	}
}

// checkReferenceCA reads and verifies the referenced CA, printing its
// fingerprint on success. It runs after the "config valid:" line, so a
// failure here (missing files, not a CA, key/cert mismatch) surfaces as a
// non-zero exit even though the configuration itself is well-formed — the
// "config valid:" line above is about the HCL, this step is about the
// files it points at. An expired CA is reported as a warning on stderr but
// is not a check failure: the files are a coherent CA the operator owns.
func checkReferenceCA(cmd *cobra.Command, cfg *config.Config) error {
	certReal := cfg.Resolve(cfg.CACertPath())
	keyReal := cfg.Resolve(cfg.CAKeyPath())

	certPEM, err := os.ReadFile(certReal)
	if err != nil {
		return fmt.Errorf("read referenced CA certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(keyReal)
	if err != nil {
		return fmt.Errorf("read referenced CA key: %w", err)
	}

	res, err := pki.LoadReferenceCA(certPEM, keyPEM, time.Now())
	if errors.Is(err, pki.ErrReferenceCAExpired) {
		fmt.Fprintf(cmd.ErrOrStderr(),
			"warning: referenced CA %q is expired (not_after %s)\n",
			res.Name, res.NotAfter.UTC().Format(time.RFC3339),
		)
	} else if err != nil {
		return err
	}

	fmt.Fprintf(cmd.OutOrStdout(),
		"  ca verified: name=%q fingerprint=%s\n", res.Name, res.Fingerprint,
	)
	return nil
}
