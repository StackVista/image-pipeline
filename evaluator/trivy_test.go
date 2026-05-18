package main

import (
	"os"
	"strings"
	"testing"
)

func TestTrivyScanner_Name(t *testing.T) {
	if got := (TrivyScanner{}).Name(); got != "trivy" {
		t.Errorf("Name = %q; want %q", got, "trivy")
	}
}

func TestTrivyScanner_ParseFixture(t *testing.T) {
	f, err := os.Open("testdata/trivy-kafka-fixture.json")
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()

	findings, err := TrivyScanner{}.Parse(f)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings from fixture; got %d", len(findings))
	}

	byCVE := map[string]Finding{}
	for _, f := range findings {
		byCVE[f.VulnerabilityID] = f
	}
	jetty, ok := byCVE["CVE-2026-2332"]
	if !ok {
		t.Fatal("CVE-2026-2332 missing from parsed findings")
	}
	if jetty.PackageName != "org.eclipse.jetty:jetty-http" {
		t.Errorf("PackageName = %q; want %q", jetty.PackageName, "org.eclipse.jetty:jetty-http")
	}
	if jetty.Severity != "HIGH" {
		t.Errorf("Severity = %q; want HIGH", jetty.Severity)
	}
	if len(jetty.SourceScanners) != 1 || jetty.SourceScanners[0] != "trivy" {
		t.Errorf("SourceScanners = %v; want [trivy]", jetty.SourceScanners)
	}
	if len(jetty.Paths) != 1 {
		t.Errorf("Paths = %v; want one entry from PkgPath", jetty.Paths)
	}
}

func TestTrivyScanner_ParseInline(t *testing.T) {
	body := `{
		"Results": [
			{
				"Target": "test",
				"Vulnerabilities": [
					{
						"VulnerabilityID": "CVE-1",
						"PkgName": "foo",
						"InstalledVersion": "1.0",
						"Severity": "critical",
						"PkgIdentifier": {"PURL": "pkg:foo/foo@1.0"}
					}
				]
			}
		]
	}`
	findings, err := TrivyScanner{}.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	if findings[0].Severity != "CRITICAL" {
		t.Errorf("Severity = %q; want CRITICAL (uppercased)", findings[0].Severity)
	}
	if findings[0].PackagePURL != "pkg:foo/foo@1.0" {
		t.Errorf("PackagePURL = %q; want pkg:foo/foo@1.0", findings[0].PackagePURL)
	}
}
