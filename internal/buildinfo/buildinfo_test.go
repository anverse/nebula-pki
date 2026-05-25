package buildinfo

import "testing"

func TestStringDefault(t *testing.T) {
	got := String()
	want := "dev none unknown"
	if got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestStringWithInjectedValues(t *testing.T) {
	origV, origC, origD := Version, Commit, Date
	t.Cleanup(func() {
		Version, Commit, Date = origV, origC, origD
	})

	Version = "v0.0.1"
	Commit = "abc1234"
	Date = "2026-05-19T00:00:00Z"

	if got, want := String(), "v0.0.1 abc1234 2026-05-19T00:00:00Z"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}
