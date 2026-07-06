// Package cli wires the cobra command tree.
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
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
		noRenewal   bool
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
			return runReconcile(cmd, configPath, dryRun, noRenewal)
		},
	}

	root.SetOut(stdout)
	root.SetErr(stderr)
	root.Flags().BoolVar(&showVersion, "version", false, "print version and exit")
	root.PersistentFlags().StringVarP(&configPath, "config", "c", defaultConfigPath, "path to HCL configuration file")
	root.Flags().BoolVar(&dryRun, "dry-run", false, "preview planned writes without modifying the filesystem")
	root.Flags().BoolVar(&noRenewal, "no-renewal", false, "skip time-based renewal; config changes, new hosts, and CA rotation re-signs are unaffected")

	root.AddCommand(newVersionCmd())
	root.AddCommand(newCheckCmd(&configPath))

	return root
}

// runReconcile is the default action: load the configuration and bring the
// output tree in line with it. It reconciles the CA in both generate and
// reference mode, and signs any host certificates that are new or missing.
// When dryRun is true the plan is previewed on stdout without any writes.
func runReconcile(cmd *cobra.Command, configPath string, dryRun, noRenewal bool) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	rep, err := apply.Reconcile(cfg, apply.Options{
		Now:              now,
		GeneratorVersion: buildinfo.Version,
		Warn:             cmd.ErrOrStderr(),
		DryRun:           dryRun,
		Out:              cmd.OutOrStdout(),
		NoRenewal:        noRenewal,
	})
	if err != nil {
		return err
	}
	if !dryRun {
		writeReconcileSummary(cmd.ErrOrStderr(), rep)
	}
	printDeadlineReport(cmd.ErrOrStderr(), rep.Deadlines, now)
	return nil
}

// writeReconcileSummary prints a short human summary of a reconcile run.
func writeReconcileSummary(w io.Writer, rep *apply.Report) {
	if !rep.Changed {
		fmt.Fprintln(w, "up to date; nothing to do")
		return
	}

	for _, ca := range rep.CAs {
		if ca.Mode == "reference" {
			fmt.Fprintf(w, "using referenced CA %q (%s)\n", ca.Label, ca.Name)
		} else {
			fmt.Fprintf(w, "generated CA %q (%s)\n", ca.Label, ca.Name)
		}
		fmt.Fprintf(w, "  cert: %s\n", ca.CertPath)
		fmt.Fprintf(w, "  key:  %s\n", ca.KeyPath)
	}
	for _, h := range rep.SignedHosts {
		fmt.Fprintf(w, "signed host %q\n", h.Label)
		for _, a := range h.Artifacts {
			fmt.Fprintf(w, "  cert: %s\n", a.CertPath)
			if a.KeyPath != "" {
				fmt.Fprintf(w, "  key:  %s\n", a.KeyPath)
			}
		}
	}
	if len(rep.StaleArtifacts) > 0 {
		fmt.Fprintln(w, "notice: the following files are no longer managed by this configuration.")
		fmt.Fprintln(w, "  They can be deleted once you have confirmed the new location is correct:")
		for _, p := range rep.StaleArtifacts {
			fmt.Fprintf(w, "  %s\n", p)
		}
	}
	if rep.TrustBundleWritten {
		fmt.Fprintf(w, "wrote trust bundle: %s\n", rep.TrustBundlePath)
	}
	fmt.Fprintf(w, "wrote manifest: %s\n", rep.ManifestPath)
}

// printDeadlineReport writes the post-run "run again before" advisory to w.
// It is printed on every reconcile and --dry-run, including no-op runs. When
// there are no managed certificates yet, nothing is printed.
func printDeadlineReport(w io.Writer, d apply.DeadlineReport, now time.Time) {
	if d.NextDeadline.IsZero() {
		return
	}

	date := d.NextDeadline.UTC().Format("2006-01-02")
	if !now.Before(d.NextDeadline) {
		fmt.Fprintf(w, "overdue: %s (deadline was %s)\n", d.NextDeadlineDesc, date)
	} else {
		days := int(d.NextDeadline.Sub(now).Hours() / 24)
		fmt.Fprintf(w, "next deadline: %s on %s (in %dd)\n", d.NextDeadlineDesc, date, days)
	}

	// Collect soon items that are not the primary deadline item.
	var others []apply.DeadlineItem
	for _, item := range d.SoonItems {
		if item.Deadline.Equal(d.NextDeadline) && item.Desc == d.NextDeadlineDesc {
			continue
		}
		others = append(others, item)
	}
	if len(others) > 0 {
		parts := make([]string, 0, len(others))
		for _, item := range others {
			itemDate := item.Deadline.UTC().Format("2006-01-02")
			days := int(item.Deadline.Sub(now).Hours() / 24)
			parts = append(parts, fmt.Sprintf("%s %s (in %dd)", item.Desc, itemDate, days))
		}
		fmt.Fprintf(w, "  also expiring soon: %s\n", strings.Join(parts, "; "))
	}

	// Overdue items that are not the primary deadline.
	for _, item := range d.OverdueItems {
		if item.Deadline.Equal(d.NextDeadline) && item.Desc == d.NextDeadlineDesc {
			continue
		}
		itemDate := item.Deadline.UTC().Format("2006-01-02")
		fmt.Fprintf(w, "  overdue: %s (deadline was %s)\n", item.Desc, itemDate)
	}

	if now.Before(d.NextDeadline) {
		fmt.Fprintf(w, "hint: run nebula-pki again before %s to keep the mesh current\n", date)
	}
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
// After validating the HCL it performs two additional file reads:
//
//   - For each reference-mode CA: reads cert_file/key_file, verifies the
//     pair is coherent, and reports the CA fingerprint.
//   - For each host with in_pub: reads the device-supplied public key file
//     and checks that its curve matches the signing CA. A curve mismatch
//     here will always cause reconcile to fail, so surfacing it in `check`
//     lets the operator catch it without touching the output tree.
//
// The configPath pointer is owned by the root command's persistent flag;
// we read it through a pointer so flag parsing has run by the time RunE
// executes.
func newCheckCmd(configPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "check",
		Short: "Parse and validate the HCL configuration",
		Long: "Parse the HCL configuration at -c/--config and run every validation rule.\n" +
			"No output tree is written. Reference CA files and in_pub public keys\n" +
			"are read to verify curve and coherence. Exits 0 on success, 1 on error.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(*configPath)
			if err != nil {
				return err
			}
			// This line reports that the HCL parsed and passed every validation
			// rule. The file reads below are about the referenced artifacts, not
			// the config itself; failures here surface after this line.
			fmt.Fprintf(cmd.OutOrStdout(),
				"config valid: %s (cas=%d, hosts=%d)\n",
				cfg.Path, len(cfg.CAs), len(cfg.Hosts),
			)

			// caCurves collects the resolved curve for every CA so in_pub host
			// checks can compare against the correct signing CA's curve without
			// re-reading the CA files.
			caCurves := make(map[string]string, len(cfg.CAs))

			for i := range cfg.CAs {
				ca := &cfg.CAs[i]
				if ca.Mode == config.CAModeReference {
					curve, err := checkReferenceCA(cmd, cfg, ca)
					if err != nil {
						return err
					}
					caCurves[ca.Label] = curve
				} else {
					// Generate mode: the curve is known from the config (default: 25519).
					if ca.HasCurve {
						caCurves[ca.Label] = pki.CurveString(ca.Curve)
					} else {
						caCurves[ca.Label] = "25519"
					}
				}
			}

			for i := range cfg.Hosts {
				if cfg.Hosts[i].InPub != "" {
					if err := checkInPubHost(cmd, cfg, &cfg.Hosts[i], caCurves); err != nil {
						return err
					}
				}
			}
			return nil
		},
	}
}

// checkReferenceCA reads and verifies one reference-mode CA, printing its
// fingerprint on success. Returns the CA's curve string so the caller can
// use it for in_pub host curve checks. An expired CA is a warning on stderr
// but not a check failure; the files are a coherent CA the operator owns.
func checkReferenceCA(cmd *cobra.Command, cfg *config.Config, ca *config.CA) (curveStr string, err error) {
	certReal := cfg.Resolve(cfg.CACertPathForCA(*ca))
	keyReal := cfg.Resolve(cfg.CAKeyPathForCA(*ca))

	certPEM, err := os.ReadFile(certReal)
	if err != nil {
		return "", fmt.Errorf("ca %q: read referenced CA certificate: %w", ca.Label, err)
	}
	keyPEM, err := os.ReadFile(keyReal)
	if err != nil {
		return "", fmt.Errorf("ca %q: read referenced CA key: %w", ca.Label, err)
	}

	res, err := pki.LoadReferenceCA(certPEM, keyPEM, time.Now())
	if errors.Is(err, pki.ErrReferenceCAExpired) {
		fmt.Fprintf(cmd.ErrOrStderr(),
			"warning: referenced CA %q (%s) is expired (not_after %s)\n",
			ca.Label, res.Name, res.NotAfter.UTC().Format(time.RFC3339),
		)
	} else if err != nil {
		return "", err
	}

	fmt.Fprintf(cmd.OutOrStdout(),
		"  ca %q verified: name=%q fingerprint=%s\n", ca.Label, res.Name, res.Fingerprint,
	)
	return res.Curve, nil
}

// checkInPubHost reads a host's device-supplied public key and verifies that
// its curve matches the signing CA's curve. A mismatch would always cause
// reconcile to fail with a curve error, so surfacing it here lets the operator
// know before any output-tree changes are attempted.
func checkInPubHost(cmd *cobra.Command, cfg *config.Config, h *config.Host, caCurves map[string]string) error {
	pubReal := cfg.Resolve(h.InPub)
	pubPEM, err := os.ReadFile(pubReal)
	if err != nil {
		return fmt.Errorf("host %q: read in_pub %s: %w", h.Label, h.InPub, err)
	}

	_, pubCurveStr, err := pki.ParseHostPublicKeyPEM(pubPEM)
	if err != nil {
		return fmt.Errorf("host %q: in_pub %s: %w", h.Label, h.InPub, err)
	}

	signingCA := cfg.SigningCA(*h) // non-nil: config.validate() passed
	expectedCurve := caCurves[signingCA.Label]
	if pubCurveStr != expectedCurve {
		return fmt.Errorf(
			"host %q: in_pub %s has curve %s but signing CA %q uses curve %s; "+
				"re-generate the device keypair with the correct curve or switch to a matching CA",
			h.Label, h.InPub, pubCurveStr, signingCA.Label, expectedCurve,
		)
	}

	fmt.Fprintf(cmd.OutOrStdout(),
		"  host %q: in_pub %s (curve=%s) OK\n", h.Label, h.InPub, pubCurveStr,
	)
	return nil
}
