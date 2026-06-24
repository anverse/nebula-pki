package config

// Tests for v0.0.10 features: ca.archived, ca.renew_before, host.renew_before.

import (
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// ca.archived
// ---------------------------------------------------------------------------

func TestCA_Archived_ParsedAndDefaultsFalse(t *testing.T) {
	cfg, err := Parse("t.hcl", []byte(`ca "mesh" { name = "m" }`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.CAs[0].Archived {
		t.Error("Archived = true, want false when not set")
	}
}

func TestCA_Archived_TrueRoundTrips(t *testing.T) {
	// Two CAs: "current" archived, "next" default (so there is a valid
	// signing CA for any host).
	src := `
ca "current" {
  name     = "old"
  archived = true
}
ca "next" {
  name    = "new"
  default = true
}
`
	cfg, err := Parse("t.hcl", []byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !cfg.CAs[0].Archived {
		t.Error("CAs[0].Archived = false, want true for 'current'")
	}
	if cfg.CAs[1].Archived {
		t.Error("CAs[1].Archived = true, want false for 'next'")
	}
}

func TestCA_Archived_CannotBeDefault(t *testing.T) {
	src := `
ca "mesh" {
  name     = "m"
  archived = true
  default  = true
}
`
	_, err := Parse("t.hcl", []byte(src))
	if err == nil {
		t.Fatal("want error for archived + default = true, got nil")
	}
	if !strings.Contains(err.Error(), "archived") || !strings.Contains(err.Error(), "default") {
		t.Errorf("error = %q, want it to mention both 'archived' and 'default'", err.Error())
	}
}

func TestCA_Archived_HostSigningViaDefaultErrors(t *testing.T) {
	// Only CA is archived; host would use it as the sole/default CA.
	src := `
ca "mesh" {
  name     = "m"
  archived = true
}
host "alpha" { networks = ["10.0.0.1/16"] }
`
	_, err := Parse("t.hcl", []byte(src))
	if err == nil {
		t.Fatal("want error when sole CA is archived and a host needs signing, got nil")
	}
	if !strings.Contains(err.Error(), "archived") {
		t.Errorf("error = %q, want it to mention 'archived'", err.Error())
	}
}

func TestCA_Archived_HostSigningViaExplicitRefErrors(t *testing.T) {
	src := `
ca "current" {
  name     = "old"
  archived = true
}
ca "next" {
  name    = "new"
  default = true
}
host "alpha" {
  ca       = "current"
  networks = ["10.0.0.1/16"]
}
`
	_, err := Parse("t.hcl", []byte(src))
	if err == nil {
		t.Fatal("want error when host.ca references an archived CA, got nil")
	}
	if !strings.Contains(err.Error(), "archived") {
		t.Errorf("error = %q, want it to mention 'archived'", err.Error())
	}
}

func TestCA_Archived_HostCanUseLiveCAWhileOtherIsArchived(t *testing.T) {
	src := `
ca "current" {
  name     = "old"
  archived = true
}
ca "next" {
  name    = "new"
  default = true
}
host "alpha" { networks = ["10.0.0.1/16"] }
`
	cfg, err := Parse("t.hcl", []byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	h := cfg.Hosts[0]
	ca := cfg.SigningCA(h)
	if ca == nil || ca.Label != "next" {
		t.Errorf("SigningCA = %v, want 'next'", ca)
	}
}

func TestCA_Archived_AllowedOnReferenceCA(t *testing.T) {
	src := `
ca "old" {
  cert_file = "ca.crt"
  key_file  = "ca.key"
  archived  = true
}
ca "new" {
  name    = "new"
  default = true
}
`
	cfg, err := Parse("t.hcl", []byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !cfg.CAs[0].Archived {
		t.Error("reference CA should be allowed to be archived")
	}
}

// ---------------------------------------------------------------------------
// ca.renew_before
// ---------------------------------------------------------------------------

func TestCA_RenewBefore_ParsedOnGenerateCA(t *testing.T) {
	src := `
ca "mesh" {
  name         = "m"
  renew_before = "720h"
}
`
	cfg, err := Parse("t.hcl", []byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	ca := cfg.CAs[0]
	if !ca.HasRenewBefore {
		t.Fatal("HasRenewBefore = false, want true")
	}
	if ca.RenewBefore != 720*time.Hour {
		t.Errorf("RenewBefore = %v, want 720h", ca.RenewBefore)
	}
}

func TestCA_RenewBefore_ParsedOnReferenceCA(t *testing.T) {
	src := `
ca "ref" {
  cert_file    = "ca.crt"
  key_file     = "ca.key"
  renew_before = "168h"
}
`
	cfg, err := Parse("t.hcl", []byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.CAs[0].RenewBefore != 168*time.Hour {
		t.Errorf("RenewBefore = %v, want 168h", cfg.CAs[0].RenewBefore)
	}
}

func TestCA_RenewBefore_InvalidDurationErrors(t *testing.T) {
	_, err := Parse("t.hcl", []byte(`
ca "mesh" {
  name         = "m"
  renew_before = "notaduration"
}
`))
	if err == nil {
		t.Fatal("want parse error for invalid renew_before duration, got nil")
	}
	if !strings.Contains(err.Error(), "renew_before") {
		t.Errorf("error = %q, want it to mention 'renew_before'", err.Error())
	}
}

func TestCA_RenewBefore_GeqDuration_GenerateMode_Errors(t *testing.T) {
	// ca.renew_before ≥ ca.duration: churn foot-gun.
	src := `
ca "mesh" {
  name         = "m"
  duration     = "100h"
  renew_before = "100h"
}
`
	_, err := Parse("t.hcl", []byte(src))
	if err == nil {
		t.Fatal("want error for renew_before >= duration, got nil")
	}
	if !strings.Contains(err.Error(), "renew_before") {
		t.Errorf("error = %q, want it to mention 'renew_before'", err.Error())
	}
}

func TestCA_RenewBefore_LessThanDuration_OK(t *testing.T) {
	src := `
ca "mesh" {
  name         = "m"
  duration     = "1000h"
  renew_before = "100h"
}
`
	if _, err := Parse("t.hcl", []byte(src)); err != nil {
		t.Fatalf("Parse: %v", err)
	}
}

// ---------------------------------------------------------------------------
// host.renew_before
// ---------------------------------------------------------------------------

func TestHost_RenewBefore_Parsed(t *testing.T) {
	src := `
ca "mesh" { name = "m" }
host "alpha" {
  networks     = ["10.0.0.1/16"]
  renew_before = "48h"
}
`
	cfg, err := Parse("t.hcl", []byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	h := cfg.Hosts[0]
	if !h.HasRenewBefore {
		t.Fatal("HasRenewBefore = false, want true")
	}
	if h.RenewBefore != 48*time.Hour {
		t.Errorf("RenewBefore = %v, want 48h", h.RenewBefore)
	}
}

func TestHost_RenewBefore_InvalidDurationErrors(t *testing.T) {
	src := `
ca "mesh" { name = "m" }
host "alpha" {
  networks     = ["10.0.0.1/16"]
  renew_before = "bad"
}
`
	_, err := Parse("t.hcl", []byte(src))
	if err == nil {
		t.Fatal("want parse error for invalid host.renew_before, got nil")
	}
	if !strings.Contains(err.Error(), "renew_before") {
		t.Errorf("error = %q, want it to mention 'renew_before'", err.Error())
	}
}

func TestHost_RenewBefore_GeqDuration_Errors(t *testing.T) {
	src := `
ca "mesh" { name = "m" }
host "alpha" {
  networks     = ["10.0.0.1/16"]
  duration     = "200h"
  renew_before = "200h"
}
`
	_, err := Parse("t.hcl", []byte(src))
	if err == nil {
		t.Fatal("want error when host.renew_before >= host.duration, got nil")
	}
	if !strings.Contains(err.Error(), "renew_before") {
		t.Errorf("error = %q, want it to mention 'renew_before'", err.Error())
	}
}

func TestHost_RenewBefore_LessThanDuration_OK(t *testing.T) {
	src := `
ca "mesh" { name = "m" }
host "alpha" {
  networks     = ["10.0.0.1/16"]
  duration     = "200h"
  renew_before = "50h"
}
`
	if _, err := Parse("t.hcl", []byte(src)); err != nil {
		t.Fatalf("Parse: %v", err)
	}
}

func TestHost_RenewBefore_GeqCADuration_Inherited_Errors(t *testing.T) {
	// host.renew_before 300h >= signing ca.duration 300h → error (no host duration set).
	src := `
ca "mesh" {
  name     = "m"
  duration = "300h"
}
host "alpha" {
  networks     = ["10.0.0.1/16"]
  renew_before = "300h"
}
`
	// host.renew_before 300h >= signing ca.duration 300h → error
	_, err := Parse("t.hcl", []byte(src))
	if err == nil {
		t.Fatal("want error when host.renew_before >= ca.duration (no host duration), got nil")
	}
	if !strings.Contains(err.Error(), "renew_before") {
		t.Errorf("error = %q, want it to mention 'renew_before'", err.Error())
	}
}

func TestHost_RenewBefore_InheritedFromCA_GeqHostDuration_Errors(t *testing.T) {
	// CA renew_before 100h inherited by host; host.duration = 50h → churn.
	src := `
ca "mesh" {
  name         = "m"
  renew_before = "100h"
}
host "alpha" {
  networks = ["10.0.0.1/16"]
  duration = "50h"
}
`
	_, err := Parse("t.hcl", []byte(src))
	if err == nil {
		t.Fatal("want error when inherited ca.renew_before >= host.duration, got nil")
	}
	if !strings.Contains(err.Error(), "renew_before") {
		t.Errorf("error = %q, want it to mention 'renew_before'", err.Error())
	}
}

func TestHost_RenewBefore_InheritedFromCA_LessThanHostDuration_OK(t *testing.T) {
	src := `
ca "mesh" {
  name         = "m"
  renew_before = "24h"
}
host "alpha" {
  networks = ["10.0.0.1/16"]
  duration = "200h"
}
`
	if _, err := Parse("t.hcl", []byte(src)); err != nil {
		t.Fatalf("Parse: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Config.ResolvedRenewBefore
// ---------------------------------------------------------------------------

func TestConfig_ResolvedRenewBefore_HostOverrideWins(t *testing.T) {
	src := `
ca "mesh" {
  name         = "m"
  renew_before = "720h"
}
host "alpha" {
  networks     = ["10.0.0.1/16"]
  renew_before = "48h"
}
`
	cfg, err := Parse("t.hcl", []byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := cfg.ResolvedRenewBefore(cfg.Hosts[0]); got != 48*time.Hour {
		t.Errorf("ResolvedRenewBefore = %v, want 48h (host override)", got)
	}
}

func TestConfig_ResolvedRenewBefore_InheritsFromCA(t *testing.T) {
	src := `
ca "mesh" {
  name         = "m"
  renew_before = "720h"
}
host "alpha" { networks = ["10.0.0.1/16"] }
`
	cfg, err := Parse("t.hcl", []byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := cfg.ResolvedRenewBefore(cfg.Hosts[0]); got != 720*time.Hour {
		t.Errorf("ResolvedRenewBefore = %v, want 720h (inherited from CA)", got)
	}
}

func TestConfig_ResolvedRenewBefore_ZeroWhenUnset(t *testing.T) {
	src := `
ca "mesh" { name = "m" }
host "alpha" { networks = ["10.0.0.1/16"] }
`
	cfg, err := Parse("t.hcl", []byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := cfg.ResolvedRenewBefore(cfg.Hosts[0]); got != 0 {
		t.Errorf("ResolvedRenewBefore = %v, want 0 (no threshold)", got)
	}
}
