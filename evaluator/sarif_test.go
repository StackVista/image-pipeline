package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildSARIF_SchemaAndVersion(t *testing.T) {
	r := buildSARIF(testImage, nil, nil, nil, "v0.1.0")
	if r.Version != "2.1.0" {
		t.Errorf("Version = %q; want 2.1.0", r.Version)
	}
	if r.Schema == "" {
		t.Errorf("Schema URL should be populated")
	}
	if len(r.Runs) != 1 {
		t.Fatalf("expected 1 run; got %d", len(r.Runs))
	}
}

func TestBuildSARIF_DriverIdentity(t *testing.T) {
	r := buildSARIF(testImage, nil, nil, nil, "v0.1.0")
	d := r.Runs[0].Tool.Driver
	if d.Name != sarifDriverName {
		t.Errorf("Driver.Name = %q; want %q", d.Name, sarifDriverName)
	}
	if d.Version != "v0.1.0" {
		t.Errorf("Driver.Version = %q; want v0.1.0", d.Version)
	}
	if d.InformationURI == "" {
		t.Errorf("Driver.InformationURI should be populated")
	}
}

func TestBuildSARIF_OneResultPerDecision(t *testing.T) {
	decisions := []Decision{
		{Finding: Finding{VulnerabilityID: "CVE-1", PackageName: "p1", Severity: "HIGH"}},
		{Finding: Finding{VulnerabilityID: "CVE-2", PackageName: "p2", Severity: "CRITICAL"}},
		{Finding: Finding{VulnerabilityID: "CVE-3", PackageName: "p3", Severity: "MEDIUM"}},
	}
	r := buildSARIF(testImage, decisions, nil, nil, "dev")
	if got := len(r.Runs[0].Results); got != 3 {
		t.Errorf("Results count = %d; want 3", got)
	}
}

func TestBuildSARIF_RulesDedupedByCVE(t *testing.T) {
	// Same CVE on two packages → one rule, two results.
	decisions := []Decision{
		{Finding: Finding{VulnerabilityID: "CVE-1", PackageName: "p1", Severity: "HIGH"}},
		{Finding: Finding{VulnerabilityID: "CVE-1", PackageName: "p2", Severity: "HIGH"}},
	}
	r := buildSARIF(testImage, decisions, nil, nil, "dev")
	if got := len(r.Runs[0].Tool.Driver.Rules); got != 1 {
		t.Errorf("Rules count = %d; want 1 (deduped by CVE)", got)
	}
	if got := len(r.Runs[0].Results); got != 2 {
		t.Errorf("Results count = %d; want 2", got)
	}
}

func TestBuildSARIF_RulesSortedByID(t *testing.T) {
	// Map iteration is random; rules must be sorted for deterministic output.
	decisions := []Decision{
		{Finding: Finding{VulnerabilityID: "CVE-3", PackageName: "p3", Severity: "HIGH"}},
		{Finding: Finding{VulnerabilityID: "CVE-1", PackageName: "p1", Severity: "HIGH"}},
		{Finding: Finding{VulnerabilityID: "CVE-2", PackageName: "p2", Severity: "HIGH"}},
	}
	r := buildSARIF(testImage, decisions, nil, nil, "dev")
	rules := r.Runs[0].Tool.Driver.Rules
	if len(rules) != 3 {
		t.Fatalf("Rules count = %d; want 3", len(rules))
	}
	for i := 1; i < len(rules); i++ {
		if rules[i-1].ID > rules[i].ID {
			t.Errorf("rules not sorted: %v", []string{rules[0].ID, rules[1].ID, rules[2].ID})
		}
	}
}

func TestBuildSARIF_LevelAndSeverityMapping(t *testing.T) {
	cases := []struct{ sev, level, secSev string }{
		{"CRITICAL", "error", "9.5"},
		{"HIGH", "error", "8.0"},
		{"MEDIUM", "warning", "5.0"},
		{"LOW", "note", "2.0"},
		{"UNKNOWN", "note", "0.0"},
	}
	for _, c := range cases {
		decisions := []Decision{{Finding: Finding{VulnerabilityID: "CVE-X", Severity: c.sev}}}
		r := buildSARIF(testImage, decisions, nil, nil, "dev")
		got := r.Runs[0].Results[0]
		if got.Level != c.level {
			t.Errorf("severity %s: Level = %q; want %q", c.sev, got.Level, c.level)
		}
		if got.Properties.SecuritySeverity != c.secSev {
			t.Errorf("severity %s: SecuritySeverity = %q; want %q", c.sev, got.Properties.SecuritySeverity, c.secSev)
		}
	}
}

func TestBuildSARIF_SuppressedHasSuppression(t *testing.T) {
	decisions := []Decision{{
		Finding:    Finding{VulnerabilityID: "CVE-1", PackageName: "p1", Severity: "HIGH"},
		Suppressed: &Suppression{Source: "exception/path/CVE-1.yaml", Justification: "accepted_pending_upstream_fix — preserve_appco_provenance"},
	}}
	r := buildSARIF(testImage, decisions, nil, nil, "dev")
	res := r.Runs[0].Results[0]
	if len(res.Suppressions) != 1 {
		t.Fatalf("expected 1 suppression; got %d", len(res.Suppressions))
	}
	s := res.Suppressions[0]
	if s.Kind != "external" {
		t.Errorf("Suppression.Kind = %q; want external", s.Kind)
	}
	if !strings.Contains(s.Justification, "accepted_pending_upstream_fix") {
		t.Errorf("Suppression.Justification = %q; want it to carry status+reason", s.Justification)
	}
	if s.Properties == nil || s.Properties.Source != "exception/path/CVE-1.yaml" {
		t.Errorf("Suppression.Properties.Source not set correctly: %+v", s.Properties)
	}
}

func TestBuildSARIF_ExpiredIsLiveResultWithStatus(t *testing.T) {
	decisions := []Decision{{
		Finding: Finding{VulnerabilityID: "CVE-1", PackageName: "p1", Severity: "HIGH"},
		Expired: &Exception{SourcePath: "exceptions/test/CVE-1.yaml", Expires: "2020-01-01"},
	}}
	r := buildSARIF(testImage, decisions, nil, nil, "dev")
	res := r.Runs[0].Results[0]
	if len(res.Suppressions) != 0 {
		t.Errorf("expired exception should NOT emit a SARIF suppression; got %+v", res.Suppressions)
	}
	if res.Properties == nil || res.Properties.Status != "expired" {
		t.Errorf("expired finding should set image-pipeline.status=expired; got %+v", res.Properties)
	}
	if !strings.Contains(res.Message.Text, "expired") {
		t.Errorf("expired message should mention expiry; got %q", res.Message.Text)
	}
}

func TestBuildSARIF_UnmanagedIsLiveResult(t *testing.T) {
	decisions := []Decision{{
		Finding: Finding{VulnerabilityID: "CVE-1", PackageName: "p1", Severity: "HIGH"},
	}}
	r := buildSARIF(testImage, decisions, nil, nil, "dev")
	res := r.Runs[0].Results[0]
	if len(res.Suppressions) != 0 {
		t.Errorf("unmanaged finding should not have suppressions; got %+v", res.Suppressions)
	}
	if res.Properties != nil && res.Properties.Status != "" {
		t.Errorf("unmanaged finding should not have a status property; got %q", res.Properties.Status)
	}
}

func TestBuildSARIF_ScannersPropagated(t *testing.T) {
	decisions := []Decision{{
		Finding: Finding{VulnerabilityID: "CVE-1", PackageName: "p1", Severity: "HIGH", SourceScanners: []string{"grype", "trivy"}},
	}}
	r := buildSARIF(testImage, decisions, nil, nil, "dev")
	got := r.Runs[0].Results[0].Properties.Scanners
	if len(got) != 2 || got[0] != "grype" || got[1] != "trivy" {
		t.Errorf("Scanners = %v; want [grype trivy]", got)
	}
}

func TestBuildSARIF_LocationsFromPathsAndPURL(t *testing.T) {
	decisions := []Decision{{
		Finding: Finding{
			VulnerabilityID: "CVE-1",
			PackageName:     "org.eclipse.jetty:jetty-http",
			Severity:        "HIGH",
			Paths:           []string{"/opt/kafka/lib/jetty-http-9.4.57.jar"},
			PackagePURL:     "pkg:maven/org.eclipse.jetty/jetty-http@9.4.57",
		},
	}}
	r := buildSARIF(testImage, decisions, nil, nil, "dev")
	locs := r.Runs[0].Results[0].Locations
	if len(locs) != 1 {
		t.Fatalf("expected 1 location; got %d", len(locs))
	}
	if locs[0].PhysicalLocation == nil || locs[0].PhysicalLocation.ArtifactLocation.URI != "/opt/kafka/lib/jetty-http-9.4.57.jar" {
		t.Errorf("physical location URI not set: %+v", locs[0].PhysicalLocation)
	}
	if len(locs[0].LogicalLocations) != 1 || locs[0].LogicalLocations[0].Name != "pkg:maven/org.eclipse.jetty/jetty-http@9.4.57" {
		t.Errorf("PURL not attached as logical location: %+v", locs[0].LogicalLocations)
	}
}

func TestBuildSARIF_LocationFallbackToPackageName(t *testing.T) {
	// No Paths, no PURL — must still emit a location so GHAS can render.
	decisions := []Decision{{
		Finding: Finding{VulnerabilityID: "CVE-1", PackageName: "lonely-pkg", Severity: "HIGH"},
	}}
	r := buildSARIF(testImage, decisions, nil, nil, "dev")
	locs := r.Runs[0].Results[0].Locations
	if len(locs) != 1 || len(locs[0].LogicalLocations) != 1 || locs[0].LogicalLocations[0].Name != "lonely-pkg" {
		t.Errorf("expected fallback to package-name logical location; got %+v", locs)
	}
}

func TestBuildSARIF_FingerprintStableAndDistinct(t *testing.T) {
	f1 := Finding{VulnerabilityID: "CVE-1", PackageName: "p", PackageVersion: "1.0"}
	f2 := Finding{VulnerabilityID: "CVE-1", PackageName: "p", PackageVersion: "1.0"}
	f3 := Finding{VulnerabilityID: "CVE-2", PackageName: "p", PackageVersion: "1.0"}
	if fingerprint(testImage, f1) != fingerprint(testImage, f2) {
		t.Errorf("fingerprint should be stable for identical input")
	}
	if fingerprint(testImage, f1) == fingerprint(testImage, f3) {
		t.Errorf("fingerprint should differ when CVE differs")
	}
	if fingerprint(testImage, f1) == fingerprint("other-image", f1) {
		t.Errorf("fingerprint should differ when image differs")
	}
}

func TestBuildSARIF_RuleHelpURIFromPrimaryURL(t *testing.T) {
	decisions := []Decision{{
		Finding: Finding{VulnerabilityID: "CVE-1", PackageName: "p", Severity: "HIGH", PrimaryURL: "https://nvd.nist.gov/vuln/detail/CVE-1"},
	}}
	r := buildSARIF(testImage, decisions, nil, nil, "dev")
	if got := r.Runs[0].Tool.Driver.Rules[0].HelpURI; got != "https://nvd.nist.gov/vuln/detail/CVE-1" {
		t.Errorf("Rule.HelpURI = %q; want NVD link", got)
	}
}

func TestWriteSARIF_ProducesValidJSON(t *testing.T) {
	decisions := []Decision{
		{
			Finding:    Finding{VulnerabilityID: "CVE-1", PackageName: "p1", Severity: "HIGH", SourceScanners: []string{"trivy"}},
			Suppressed: &Suppression{Source: "exception/x", Justification: "j"},
		},
		{Finding: Finding{VulnerabilityID: "CVE-2", PackageName: "p2", Severity: "CRITICAL", SourceScanners: []string{"trivy"}}},
	}
	var buf bytes.Buffer
	if err := writeSARIF(&buf, testImage, decisions, nil, nil, "v0.1.0"); err != nil {
		t.Fatalf("writeSARIF: %v", err)
	}
	// Round-trip the output through json.Decoder to confirm structural validity.
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if got["version"] != "2.1.0" {
		t.Errorf("decoded version = %v; want 2.1.0", got["version"])
	}
}

func TestWriteSARIF_DoesNotEscapeHTML(t *testing.T) {
	// HelpURI / paths can contain & or < which should not be escaped to
	// & / < by the JSON encoder — the SARIF should be readable
	// when uploaded to GHAS.
	decisions := []Decision{{
		Finding: Finding{VulnerabilityID: "CVE-1", PackageName: "p", Severity: "HIGH", PrimaryURL: "https://example.com/?a=1&b=2"},
	}}
	var buf bytes.Buffer
	if err := writeSARIF(&buf, testImage, decisions, nil, nil, "dev"); err != nil {
		t.Fatalf("writeSARIF: %v", err)
	}
	if !strings.Contains(buf.String(), "?a=1&b=2") {
		t.Errorf("expected unescaped & in output; got:\n%s", buf.String())
	}
}

func TestBuildSARIF_UnusedExceptionsInRunProperties(t *testing.T) {
	decisions := []Decision{
		{Finding: Finding{VulnerabilityID: "CVE-1", PackageName: "p1", Severity: "HIGH"}},
	}
	unused := []ExceptionKey{
		{Image: testImage, CVE: "CVE-99"},
		{Image: testImage, CVE: "CVE-100"},
	}
	exceptions := map[ExceptionKey]Exception{
		{Image: testImage, CVE: "CVE-99"}:  {SourcePath: "exception/cve-99"},
		{Image: testImage, CVE: "CVE-100"}: {SourcePath: "exception/cve-100"},
	}
	r := buildSARIF(testImage, decisions, unused, exceptions, "dev")
	props := r.Runs[0].Properties
	if props == nil || len(props.UnusedExceptions) != 2 {
		t.Fatalf("expected 2 unused exceptions in run.properties; got %+v", props)
	}
	if props.UnusedExceptions[0].CVE != "CVE-99" {
		t.Errorf("first unused CVE = %q; want CVE-99", props.UnusedExceptions[0].CVE)
	}
	if props.UnusedExceptions[0].Source != "exception/cve-99" {
		t.Errorf("source path not propagated: %+v", props.UnusedExceptions[0])
	}
}

func TestBuildSARIF_NoUnusedNoProperties(t *testing.T) {
	// All exceptions matched a finding → no run.properties.unusedExceptions.
	decisions := []Decision{
		{Finding: Finding{VulnerabilityID: "CVE-1", PackageName: "p1", Severity: "HIGH"}, Suppressed: &Suppression{Source: "exception/cve-1"}},
	}
	r := buildSARIF(testImage, decisions, nil, nil, "dev")
	if r.Runs[0].Properties != nil {
		t.Errorf("expected nil run properties when no unused exceptions; got %+v", r.Runs[0].Properties)
	}
}
