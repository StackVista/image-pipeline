package main

import (
	"encoding/json"
	"io"
	"strings"
)

// TrivyScanner adapts Trivy JSON output to the Scanner interface.
type TrivyScanner struct{}

func (TrivyScanner) Name() string { return "trivy" }

// Parse reads Trivy's JSON report and returns normalised findings.
// Severity is uppercased; PkgPath becomes a single-element Paths
// slice when present.
func (s TrivyScanner) Parse(r io.Reader) ([]Finding, error) {
	var report trivyReport
	if err := json.NewDecoder(r).Decode(&report); err != nil {
		return nil, err
	}
	var out []Finding
	for _, res := range report.Results {
		for _, v := range res.Vulnerabilities {
			f := Finding{
				VulnerabilityID: v.VulnerabilityID,
				PackageName:     v.PkgName,
				PackageVersion:  v.InstalledVersion,
				Severity:        strings.ToUpper(v.Severity),
				FixedVersions:   splitFixedVersions(v.FixedVersion),
				PrimaryURL:      v.PrimaryURL,
				PackagePURL:     v.PkgIdentifier.PURL,
				SourceScanners:  []string{s.Name()},
			}
			if v.PkgPath != "" {
				f.Paths = []string{v.PkgPath}
			}
			out = append(out, f)
		}
	}
	return out, nil
}

// splitFixedVersions parses Trivy's comma-separated FixedVersion
// string into a slice. Trivy emits e.g. "9.4.58, 12.0.x"; we split
// on `,`, trim whitespace, and drop empty entries.
func splitFixedVersions(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

type trivyReport struct {
	Results []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target          string               `json:"Target"`
	Vulnerabilities []trivyVulnerability `json:"Vulnerabilities"`
}

type trivyVulnerability struct {
	VulnerabilityID  string             `json:"VulnerabilityID"`
	PkgName          string             `json:"PkgName"`
	PkgPath          string             `json:"PkgPath,omitempty"`
	InstalledVersion string             `json:"InstalledVersion,omitempty"`
	FixedVersion     string             `json:"FixedVersion,omitempty"`
	Severity         string             `json:"Severity"`
	PrimaryURL       string             `json:"PrimaryURL,omitempty"`
	PkgIdentifier    trivyPkgIdentifier `json:"PkgIdentifier,omitempty"`
}

type trivyPkgIdentifier struct {
	PURL string `json:"PURL,omitempty"`
}
