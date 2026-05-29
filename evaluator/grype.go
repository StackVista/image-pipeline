package main

import (
	"encoding/json"
	"io"
	"sort"
	"strings"
)

// GrypeScanner adapts Grype JSON output to the Scanner interface.
type GrypeScanner struct{}

func (GrypeScanner) Name() string { return "grype" }

func (s GrypeScanner) getFindingsFromReport(report *grypeReport) []Finding {
	var out []Finding
	for _, m := range report.Matches {
		f := Finding{
			VulnerabilityID: canonicalVulnerabilityID(m.Vulnerability.ID, m.RelatedVulnerabilities),
			PackageName:     m.Artifact.Name,
			PackageVersion:  m.Artifact.Version,
			PackagePURL:     m.Artifact.PURL,
			Severity:        strings.ToUpper(m.Vulnerability.Severity),
			FixedVersions:   m.Vulnerability.Fix.Versions,
			PrimaryURL:      m.Vulnerability.DataSource,
			SourceScanners:  []string{s.Name()},
		}
		for _, loc := range m.Artifact.Locations {
			if loc.Path != "" {
				f.Paths = append(f.Paths, loc.Path)
			}
		}
		out = append(out, f)
	}
	return out
}

// Parse reads Grype's JSON report and returns normalised findings.
// Severity is uppercased; artifact.locations[].path becomes Paths;
// fix.versions are joined into a single FixedVersion string to match
// Trivy's representation.
func (s GrypeScanner) Parse(r io.Reader) ([]Finding, error) {
	var report grypeReport
	if err := json.NewDecoder(r).Decode(&report); err != nil {
		return nil, err
	}
	return s.getFindingsFromReport(&report), nil
}

type grypeReport struct {
	Matches []grypeMatch `json:"matches"`
}

type grypeMatch struct {
	Vulnerability          grypeVulnerability          `json:"vulnerability"`
	RelatedVulnerabilities []grypeRelatedVulnerability `json:"relatedVulnerabilities,omitempty"`
	Artifact               grypeArtifact               `json:"artifact"`
}

type grypeRelatedVulnerability struct {
	ID string `json:"id"`
}

type grypeVulnerability struct {
	ID         string   `json:"id"`
	Severity   string   `json:"severity"`
	DataSource string   `json:"dataSource,omitempty"`
	Fix        grypeFix `json:"fix,omitempty"`
}

type grypeFix struct {
	Versions []string `json:"versions,omitempty"`
}

type grypeArtifact struct {
	Name      string          `json:"name"`
	Version   string          `json:"version"`
	PURL      string          `json:"purl,omitempty"`
	Locations []grypeLocation `json:"locations,omitempty"`
}

type grypeLocation struct {
	Path string `json:"path,omitempty"`
}

// canonicalVulnerabilityID chooses a stable ID for a Grype match.
//
// Grype can report the same issue using different identifiers depending
// on the provider namespace (for example GHSA as primary ID with a CVE in
// relatedVulnerabilities). Since Trivy reports CVEs, we prefer a CVE ID
// when available so cross-scanner deduplication and exception matching converge.
//
// Typical grype report structure:
//
//	"vulnerability": {
//		"id": "GHSA-qh8g-58pp-2wxh",
//       ...
//	}
// "relatedVulnerabilities": [
// 	{
// 		"id": "CVE-2024-6763",
// 		...
// 	}
// ]
//
// In CI we call grype with `--by-cve` so `vulnerability.ID` should be
// already a CVE ID if available. In any case we keep this fallback code.

func canonicalVulnerabilityID(primaryID string, related []grypeRelatedVulnerability) string {
	if isCVE(primaryID) {
		return primaryID
	}

	var cves []string
	for _, rv := range related {
		if isCVE(rv.ID) {
			cves = append(cves, rv.ID)
		}
	}
	if len(cves) == 0 {
		return primaryID
	}

	sort.Strings(cves)
	return cves[0]
}

func isCVE(id string) bool {
	return strings.HasPrefix(strings.ToUpper(id), "CVE-")
}
