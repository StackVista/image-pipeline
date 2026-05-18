package main

import (
	"fmt"
	"time"
)

// Mode names accepted by --mode.
const (
	ModeGate   = "gate"
	ModeInform = "inform"
)

// Decision is the per-finding outcome of policy evaluation.
type Decision struct {
	Finding    Finding
	Suppressed *Suppression // non-nil if matched and not expired
	Expired    *Exception   // non-nil if matched but expired
}

// Suppression carries the source attribution for a successful suppression.
type Suppression struct {
	Source        string
	Justification string
}

// Evaluate matches each finding against the exception map (keyed by
// (image, CVE)), honours expiry, and returns a Decision per finding.
// `image` is the normalised name of the image being scanned. Findings
// whose severity is not in `severities` are excluded.
//
// A missing or unparseable expiry date is treated as already expired
// so the gate fails closed rather than silently passing.
func Evaluate(image string, findings []Finding, exceptions map[ExceptionKey]Exception, severities map[string]bool) []Decision {
	today := time.Now().UTC().Truncate(24 * time.Hour)
	var decisions []Decision
	for _, f := range findings {
		if !severities[f.Severity] {
			continue
		}
		d := Decision{Finding: f}
		key := ExceptionKey{Image: image, CVE: f.VulnerabilityID}
		if ex, ok := exceptions[key]; ok {
			expires, err := time.Parse("2006-01-02", ex.Expires)
			if err != nil || today.After(expires) {
				exCopy := ex
				d.Expired = &exCopy
			} else {
				d.Suppressed = &Suppression{
					Source:        "exception/" + ex.SourcePath,
					Justification: fmt.Sprintf("%s — %s", ex.Status, ex.Reason),
				}
			}
		}
		decisions = append(decisions, d)
	}
	return decisions
}

// ExitCode returns the process exit code for the given mode and
// summary. Gate mode fails on any unmanaged or expired finding;
// inform mode always returns 0 — visibility is the deliverable, not
// a gate.
func ExitCode(mode string, summary Summary) int {
	if mode == ModeInform {
		return 0
	}
	if summary.Unmanaged > 0 || summary.Expired > 0 {
		return 1
	}
	return 0
}
