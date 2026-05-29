package main

import (
	"io"
	"slices"
	"sort"
)

// Scanner adapts a vulnerability scanner's JSON output to the
// internal Finding model. The evaluator and summary are scanner-
// agnostic; new scanners are added by implementing this interface.
type Scanner interface {
	Name() string
	Parse(io.Reader) ([]Finding, error)
}

// Finding is the normalized representation of a single vulnerability
// finding, independent of which scanner reported it. Scanner adapters
// produce []Finding; the evaluator works only on Findings.
type Finding struct {
	VulnerabilityID string   // CVE-... / GHSA-... / vendor id
	PackageName     string   // e.g. "org.eclipse.jetty:jetty-http"
	PackageVersion  string   // e.g. "9.4.57.v20241219"
	PackagePURL     string   // e.g. "pkg:maven/org.eclipse.jetty/jetty-http@9.4.57"
	Paths           []string // file paths inside the image (optional)
	Severity        string   // HIGH, CRITICAL, etc. — uppercased by parser
	FixedVersions   []string // zero or more upstream-fixed versions (e.g. ["9.4.58", "12.0.x"])
	PrimaryURL      string   // optional, link to advisory

	// SourceScanners records which scanner(s) reported this finding.
	// Multiple entries when scanners agree (after DedupeFindings).
	SourceScanners []string
}

// findingKey collapses identical findings reported by multiple
// scanners. Same vulnerability ID on the same package PURL is the same
// finding regardless of which tool surfaced it.
type findingKey struct {
	vulnID, purl string
}

func (f Finding) key() findingKey {
	return findingKey{f.VulnerabilityID, f.PackagePURL}
}

// DedupeFindings collapses identical findings reported by multiple
// scanners into a single Finding. Slice-valued fields (SourceScanners,
// FixedVersions, Paths) are unioned across scanners — losing the
// information of either side would be a downgrade. Scalar fields
// (PackagePURL, Severity, PrimaryURL, FixedVersion) are kept from the
// first-seen scanner; in practice these agree, but if they ever
// diverge, the asymmetry is intentional and downstream consumers can
// inspect SourceScanners to see who reported what.
//
// Output is sorted by (vulnID, purl) for deterministic downstream
// processing.
func DedupeFindings(findings []Finding) []Finding {
	merged := map[findingKey]*Finding{}
	for i := range findings {
		f := findings[i]
		k := f.key()
		if existing, ok := merged[k]; ok {
			existing.SourceScanners = mergeStrings(existing.SourceScanners, f.SourceScanners)
			existing.FixedVersions = mergeStrings(existing.FixedVersions, f.FixedVersions)
			existing.Paths = mergeStrings(existing.Paths, f.Paths)
			continue
		}
		copyF := f
		merged[k] = &copyF
	}
	out := make([]Finding, 0, len(merged))
	for _, f := range merged {
		out = append(out, *f)
	}
	sort.Slice(out, func(i, j int) bool {
		ki, kj := out[i].key(), out[j].key()
		if ki.vulnID != kj.vulnID {
			return ki.vulnID < kj.vulnID
		}
		return ki.purl < kj.purl
	})
	return out
}

// mergeStrings returns the sorted, deduplicated union of two string slices.
func mergeStrings(a, b []string) []string {
	out := slices.Concat(a, b)
	slices.Sort(out)
	return slices.Compact(out)
}
