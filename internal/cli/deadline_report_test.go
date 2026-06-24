package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/anverse/nebula-pki/internal/apply"
)

var (
	drNow      = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	drFar      = drNow.Add(90 * 24 * time.Hour)  // 90d out — beyond soon window
	drSoon1    = drNow.Add(30 * 24 * time.Hour)  // 30d — within soon window
	drSoon2    = drNow.Add(45 * 24 * time.Hour)  // 45d — within soon window
	drOverdue  = drNow.Add(-5 * 24 * time.Hour)  // 5d ago — overdue
	drOverdue2 = drNow.Add(-10 * 24 * time.Hour) // 10d ago — more overdue
)

func printDeadlineReportStr(d apply.DeadlineReport) string {
	var buf bytes.Buffer
	printDeadlineReport(&buf, d, drNow)
	return buf.String()
}

func TestPrintDeadlineReport_Empty(t *testing.T) {
	out := printDeadlineReportStr(apply.DeadlineReport{})
	if out != "" {
		t.Errorf("expected empty output for zero report, got %q", out)
	}
}

func TestPrintDeadlineReport_NextOnly_FarFuture(t *testing.T) {
	d := apply.DeadlineReport{
		NextDeadline:     drFar,
		NextDeadlineDesc: `host "alpha" expires`,
	}
	out := printDeadlineReportStr(d)
	if !strings.Contains(out, "next deadline:") {
		t.Errorf("output = %q; want 'next deadline:'", out)
	}
	if !strings.Contains(out, "in 90d") {
		t.Errorf("output = %q; want 'in 90d'", out)
	}
	if !strings.Contains(out, "hint: run nebula-pki again before") {
		t.Errorf("output = %q; want hint line", out)
	}
	if strings.Contains(out, "also expiring soon") {
		t.Errorf("output = %q; want no 'also expiring soon' (no soon items)", out)
	}
	if strings.Contains(out, "overdue") {
		t.Errorf("output = %q; want no 'overdue'", out)
	}
}

func TestPrintDeadlineReport_SoonItems_Dedup(t *testing.T) {
	// Primary is within the soon window. SoonItems includes the primary and
	// a second item. The primary must not appear in "also expiring soon".
	d := apply.DeadlineReport{
		NextDeadline:     drSoon1,
		NextDeadlineDesc: `host "alpha" expires`,
		SoonItems: []apply.DeadlineItem{
			{Deadline: drSoon1, Desc: `host "alpha" expires`}, // duplicate of primary
			{Deadline: drSoon2, Desc: `host "beta" expires`},
		},
	}
	out := printDeadlineReportStr(d)
	if !strings.Contains(out, "next deadline:") {
		t.Errorf("output = %q; want 'next deadline:'", out)
	}
	if !strings.Contains(out, "also expiring soon") {
		t.Errorf("output = %q; want 'also expiring soon'", out)
	}
	// Primary must appear in "next deadline" line, not be repeated in "also expiring soon".
	lines := strings.Split(out, "\n")
	var soonLine string
	for _, l := range lines {
		if strings.Contains(l, "also expiring soon") {
			soonLine = l
		}
	}
	if strings.Contains(soonLine, `host "alpha" expires`) {
		t.Errorf("primary deadline %q should not appear in 'also expiring soon' line: %q", `host "alpha" expires`, soonLine)
	}
	if !strings.Contains(soonLine, `host "beta" expires`) {
		t.Errorf("second item %q should appear in 'also expiring soon' line: %q", `host "beta" expires`, soonLine)
	}
}

func TestPrintDeadlineReport_SoonItems_NoneAfterDedup(t *testing.T) {
	// SoonItems contains only the primary deadline; after dedup nothing remains.
	d := apply.DeadlineReport{
		NextDeadline:     drSoon1,
		NextDeadlineDesc: `host "alpha" expires`,
		SoonItems: []apply.DeadlineItem{
			{Deadline: drSoon1, Desc: `host "alpha" expires`},
		},
	}
	out := printDeadlineReportStr(d)
	if strings.Contains(out, "also expiring soon") {
		t.Errorf("output = %q; want no 'also expiring soon' after dedup removes the only item", out)
	}
}

func TestPrintDeadlineReport_Overdue(t *testing.T) {
	d := apply.DeadlineReport{
		NextDeadline:     drOverdue,
		NextDeadlineDesc: `CA "old" expires`,
		OverdueItems: []apply.DeadlineItem{
			{Deadline: drOverdue, Desc: `CA "old" expires`},
		},
	}
	out := printDeadlineReportStr(d)
	if !strings.HasPrefix(out, "overdue:") {
		t.Errorf("output = %q; want primary line to start with 'overdue:'", out)
	}
	// Hint suppressed when primary is overdue.
	if strings.Contains(out, "hint: run nebula-pki") {
		t.Errorf("output = %q; want no hint when primary is overdue", out)
	}
}

func TestPrintDeadlineReport_OverduePlusMore(t *testing.T) {
	// Two overdue items; the most-overdue (earliest) is primary.
	d := apply.DeadlineReport{
		NextDeadline:     drOverdue2,
		NextDeadlineDesc: `CA "very-old" expires`,
		OverdueItems: []apply.DeadlineItem{
			{Deadline: drOverdue2, Desc: `CA "very-old" expires`},
			{Deadline: drOverdue, Desc: `host "stale" expires`},
		},
	}
	out := printDeadlineReportStr(d)
	if !strings.HasPrefix(out, "overdue:") {
		t.Errorf("output = %q; want 'overdue:' on first line", out)
	}
	if !strings.Contains(out, `overdue: host "stale" expires`) {
		t.Errorf("output = %q; want secondary overdue line for host", out)
	}
	// Primary must not appear twice.
	if count := strings.Count(out, `CA "very-old" expires`); count != 1 {
		t.Errorf("primary deadline appears %d times in output, want exactly 1:\n%s", count, out)
	}
}

func TestPrintDeadlineReport_OverduePlusSoon(t *testing.T) {
	// Primary is overdue; a separate item is coming up soon.
	d := apply.DeadlineReport{
		NextDeadline:     drOverdue,
		NextDeadlineDesc: `CA "old" expires`,
		OverdueItems: []apply.DeadlineItem{
			{Deadline: drOverdue, Desc: `CA "old" expires`},
		},
		SoonItems: []apply.DeadlineItem{
			{Deadline: drSoon1, Desc: `host "alpha" expires`},
		},
	}
	out := printDeadlineReportStr(d)
	if !strings.HasPrefix(out, "overdue:") {
		t.Errorf("output = %q; want 'overdue:' on first line", out)
	}
	if !strings.Contains(out, "also expiring soon") {
		t.Errorf("output = %q; want 'also expiring soon' for the near-future item", out)
	}
	if strings.Contains(out, "hint: run nebula-pki") {
		t.Errorf("output = %q; want no hint when primary is overdue", out)
	}
}
