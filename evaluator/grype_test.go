package main

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestGrypeScanner_Name(t *testing.T) {
	if got := (GrypeScanner{}).Name(); got != "grype" {
		t.Errorf("Name = %q; want %q", got, "grype")
	}
}

func TestGrypeScanner_ParseFixture(t *testing.T) {
	f, err := os.Open("testdata/grype-kafka-fixture.json")
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()

	findings, err := GrypeScanner{}.Parse(f)
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
	if len(jetty.SourceScanners) != 1 || jetty.SourceScanners[0] != "grype" {
		t.Errorf("SourceScanners = %v; want [grype]", jetty.SourceScanners)
	}
	if len(jetty.Paths) != 1 {
		t.Errorf("Paths = %v; want one entry from artifact.locations", jetty.Paths)
	}
}

func TestGrypeScanner_ParseInline(t *testing.T) {
	body := `{
		"matches": [
			{
				"vulnerability": {
					"id": "CVE-1",
					"severity": "critical",
					"dataSource": "https://example.com/cve-1",
					"fix": {"versions": ["1.0.1", "1.1.0"], "state": "fixed"}
				},
				"artifact": {
					"name": "foo",
					"version": "1.0.0",
					"purl": "pkg:foo/foo@1.0.0",
					"locations": [{"path": "/usr/lib/foo"}, {"path": "/opt/foo"}]
				}
			}
		]
	}`
	findings, err := GrypeScanner{}.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != "CRITICAL" {
		t.Errorf("Severity = %q; want CRITICAL (uppercased)", f.Severity)
	}
	if f.PackagePURL != "pkg:foo/foo@1.0.0" {
		t.Errorf("PackagePURL = %q; want pkg:foo/foo@1.0.0", f.PackagePURL)
	}
	if want := []string{"1.0.1", "1.1.0"}; !reflect.DeepEqual(f.FixedVersions, want) {
		t.Errorf("FixedVersions = %v; want %v", f.FixedVersions, want)
	}
	if f.PrimaryURL != "https://example.com/cve-1" {
		t.Errorf("PrimaryURL = %q; want https://example.com/cve-1", f.PrimaryURL)
	}
	if len(f.Paths) != 2 || f.Paths[0] != "/usr/lib/foo" || f.Paths[1] != "/opt/foo" {
		t.Errorf("Paths = %v; want [/usr/lib/foo /opt/foo]", f.Paths)
	}
}
