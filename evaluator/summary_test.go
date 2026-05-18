package main

import (
	"strings"
	"testing"
)

func TestSummarise_Buckets(t *testing.T) {
	decisions := []Decision{
		{Finding: Finding{VulnerabilityID: "CVE-1", Severity: "HIGH"}, Suppressed: &Suppression{Source: "exception/x"}},
		{Finding: Finding{VulnerabilityID: "CVE-2", Severity: "HIGH"}, Expired: &Exception{}},
		{Finding: Finding{VulnerabilityID: "CVE-3", Severity: "CRITICAL"}}, // unmanaged
		{Finding: Finding{VulnerabilityID: "CVE-4", Severity: "HIGH"}},     // unmanaged
	}
	s := Summarise(testImage, decisions, nil)
	if s.Total != 4 || s.Suppressed != 1 || s.Expired != 1 || s.Unmanaged != 2 {
		t.Errorf("buckets wrong: total=%d suppressed=%d expired=%d unmanaged=%d",
			s.Total, s.Suppressed, s.Expired, s.Unmanaged)
	}
}

func TestSummarise_FormatHeaderShowsMode(t *testing.T) {
	out := Summarise(testImage, nil, nil).Format(ModeInform)
	if !strings.Contains(out, "(mode: inform)") {
		t.Errorf("Format header should include mode; got:\n%s", out)
	}
}

func TestSummarise_FormatSections(t *testing.T) {
	decisions := []Decision{
		{Finding: Finding{VulnerabilityID: "CVE-1", Severity: "HIGH", PackageName: "p1"}, Suppressed: &Suppression{Source: "exception/x", Justification: "j"}},
		{Finding: Finding{VulnerabilityID: "CVE-2", Severity: "HIGH", PackageName: "p2"}, Expired: &Exception{SourcePath: "exceptions/test/CVE-2.yaml", Expires: "2020-01-01"}},
		{Finding: Finding{VulnerabilityID: "CVE-3", Severity: "CRITICAL", PackageName: "p3", SourceScanners: []string{"trivy"}}},
	}
	out := Summarise(testImage, decisions, nil).Format(ModeGate)
	for _, want := range []string{
		"image-pipeline evaluator (mode: gate)",
		"Unmanaged findings:",
		"CVE-3",
		"Expired exceptions:",
		"CVE-2",
		"Suppressed:",
		"CVE-1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Format output missing %q.\nGot:\n%s", want, out)
		}
	}
}

func TestSummarise_FormatOmitsEmptySections(t *testing.T) {
	decisions := []Decision{
		{Finding: Finding{VulnerabilityID: "CVE-1", Severity: "HIGH"}, Suppressed: &Suppression{Source: "exception/x"}},
	}
	exceptions := map[ExceptionKey]Exception{
		{Image: testImage, CVE: "CVE-1"}: {SourcePath: "exception/x"},
	}
	out := Summarise(testImage, decisions, exceptions).Format(ModeGate)
	if strings.Contains(out, "Unmanaged findings:") {
		t.Errorf("Format included Unmanaged section when there were none.\nGot:\n%s", out)
	}
	if strings.Contains(out, "Expired exceptions:") {
		t.Errorf("Format included Expired section when there were none.\nGot:\n%s", out)
	}
	if strings.Contains(out, "Unused exceptions") {
		t.Errorf("Format included Unused section when all exceptions matched.\nGot:\n%s", out)
	}
}

func TestSummarise_UnusedExceptions(t *testing.T) {
	decisions := []Decision{
		{Finding: Finding{VulnerabilityID: "CVE-1", Severity: "HIGH"}, Suppressed: &Suppression{Source: "exception/cve-1"}},
	}
	exceptions := map[ExceptionKey]Exception{
		{Image: testImage, CVE: "CVE-1"}: {SourcePath: "exception/cve-1"},
		// CVE-99 is loaded but no scanner finding fired for it — stale.
		{Image: testImage, CVE: "CVE-99"}: {
			SourcePath:    "exception/cve-99",
			Vulnerability: VulnRef{ID: "CVE-99", Severity: "HIGH"},
		},
	}
	s := Summarise(testImage, decisions, exceptions)
	if s.Unused != 1 {
		t.Fatalf("Unused = %d; want 1 (CVE-99 has no matching finding)", s.Unused)
	}
	if got := s.UnusedKeys[0].CVE; got != "CVE-99" {
		t.Errorf("UnusedKeys[0].CVE = %q; want CVE-99", got)
	}
	out := s.Format(ModeInform)
	if !strings.Contains(out, "Unused exceptions") {
		t.Errorf("Format missing 'Unused exceptions' section:\n%s", out)
	}
	if !strings.Contains(out, "CVE-99") {
		t.Errorf("Format Unused section missing CVE-99:\n%s", out)
	}
	if !strings.Contains(out, "exception/cve-99") {
		t.Errorf("Format Unused section missing source path:\n%s", out)
	}
	// Unused count surfaces in the header bucket list.
	if !strings.Contains(out, "unused exceptions:        1") {
		t.Errorf("Format header missing unused count:\n%s", out)
	}
}

func TestSummarise_UnusedExceptions_DeterministicOrder(t *testing.T) {
	exceptions := map[ExceptionKey]Exception{
		{Image: testImage, CVE: "CVE-3"}: {SourcePath: "c"},
		{Image: testImage, CVE: "CVE-1"}: {SourcePath: "a"},
		{Image: testImage, CVE: "CVE-2"}: {SourcePath: "b"},
	}
	s := Summarise(testImage, nil, exceptions)
	if len(s.UnusedKeys) != 3 {
		t.Fatalf("want 3 unused; got %d", len(s.UnusedKeys))
	}
	for i, want := range []string{"CVE-1", "CVE-2", "CVE-3"} {
		if s.UnusedKeys[i].CVE != want {
			t.Errorf("UnusedKeys[%d] = %s; want %s (sorted output expected)", i, s.UnusedKeys[i].CVE, want)
		}
	}
}
