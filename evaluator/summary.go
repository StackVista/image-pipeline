package main

import (
	"fmt"
	"sort"
	"strings"
)

type Summary struct {
	Total      int
	Suppressed int
	Unmanaged  int
	Expired    int
	Unused     int
	Decisions  []Decision
	UnusedKeys []ExceptionKey
	Exceptions map[ExceptionKey]Exception
}

// Summarise aggregates decisions into bucket counts and computes the
// set of loaded exceptions that didn't match any finding in this scan
// — typically because the underlying CVE has been fixed (e.g. via a
// dependency upgrade) and the exception is now stale policy.
func Summarise(scanImage string, decisions []Decision, exceptions map[ExceptionKey]Exception) Summary {
	s := Summary{Decisions: decisions, Exceptions: exceptions}
	used := map[ExceptionKey]bool{}
	for _, d := range decisions {
		s.Total++
		switch {
		case d.Suppressed != nil:
			s.Suppressed++
			used[ExceptionKey{Image: scanImage, CVE: d.Finding.VulnerabilityID}] = true
		case d.Expired != nil:
			s.Expired++
			used[ExceptionKey{Image: scanImage, CVE: d.Finding.VulnerabilityID}] = true
		default:
			s.Unmanaged++
		}
	}
	for k := range exceptions {
		if !used[k] {
			s.UnusedKeys = append(s.UnusedKeys, k)
		}
	}
	sort.Slice(s.UnusedKeys, func(i, j int) bool {
		if s.UnusedKeys[i].Image != s.UnusedKeys[j].Image {
			return s.UnusedKeys[i].Image < s.UnusedKeys[j].Image
		}
		return s.UnusedKeys[i].CVE < s.UnusedKeys[j].CVE
	})
	s.Unused = len(s.UnusedKeys)
	return s
}

// Format renders the summary as plain text for a CI job log. Sections
// are emitted only when non-empty. The mode is shown in the header so
// readers know whether the run is gating or just reporting.
func (s Summary) Format(mode string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "image-pipeline evaluator (mode: %s)\n", mode)
	fmt.Fprintf(&b, "  total in-scope findings:  %d\n", s.Total)
	fmt.Fprintf(&b, "  suppressed by exception:  %d\n", s.Suppressed)
	fmt.Fprintf(&b, "  expired:                  %d\n", s.Expired)
	fmt.Fprintf(&b, "  unmanaged:                %d\n", s.Unmanaged)
	fmt.Fprintf(&b, "  unused exceptions:        %d\n", s.Unused)
	fmt.Fprintln(&b)
	if s.Unmanaged > 0 {
		fmt.Fprintln(&b, "Unmanaged findings:")
		for _, d := range s.Decisions {
			if d.Suppressed == nil && d.Expired == nil {
				fmt.Fprintf(&b, "  - %s [%s] %s [%s]\n",
					d.Finding.VulnerabilityID, d.Finding.Severity, d.Finding.PackageName,
					strings.Join(d.Finding.SourceScanners, ","))
			}
		}
		fmt.Fprintln(&b)
	}
	if s.Expired > 0 {
		fmt.Fprintln(&b, "Expired exceptions:")
		for _, d := range s.Decisions {
			if d.Expired != nil {
				fmt.Fprintf(&b, "  - %s [%s] %s — exception %s expired %s\n",
					d.Finding.VulnerabilityID, d.Finding.Severity, d.Finding.PackageName,
					d.Expired.SourcePath, d.Expired.Expires)
			}
		}
		fmt.Fprintln(&b)
	}
	if s.Suppressed > 0 {
		fmt.Fprintln(&b, "Suppressed:")
		for _, d := range s.Decisions {
			if d.Suppressed != nil {
				fmt.Fprintf(&b, "  - %s [%s] %s — %s (%s)\n",
					d.Finding.VulnerabilityID, d.Finding.Severity, d.Finding.PackageName,
					d.Suppressed.Source, d.Suppressed.Justification)
			}
		}
		fmt.Fprintln(&b)
	}
	if s.Unused > 0 {
		fmt.Fprintln(&b, "Unused exceptions (no matching finding in this scan — candidates for cleanup):")
		for _, k := range s.UnusedKeys {
			ex := s.Exceptions[k]
			fmt.Fprintf(&b, "  - %s [%s] %s — %s\n",
				k.CVE, ex.Vulnerability.Severity, k.Image, ex.SourcePath)
		}
		fmt.Fprintln(&b)
	}
	return b.String()
}
