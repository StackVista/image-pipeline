package main

import (
	"encoding/json"
	"io"
	"strings"
)

// GrypeScanner adapts Grype JSON output to the Scanner interface.
type GrypeScanner struct{}

func (GrypeScanner) Name() string { return "grype" }

// Parse reads Grype's JSON report and returns normalised findings.
// Severity is uppercased; artifact.locations[].path becomes Paths;
// fix.versions are joined into a single FixedVersion string to match
// Trivy's representation.
func (s GrypeScanner) Parse(r io.Reader) ([]Finding, error) {
	var report grypeReport
	if err := json.NewDecoder(r).Decode(&report); err != nil {
		return nil, err
	}
	var out []Finding
	for _, m := range report.Matches {
		f := Finding{
			VulnerabilityID: m.Vulnerability.ID,
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
	return out, nil
}

type grypeReport struct {
	Matches []grypeMatch `json:"matches"`
}

type grypeMatch struct {
	Vulnerability grypeVulnerability `json:"vulnerability"`
	Artifact      grypeArtifact      `json:"artifact"`
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
