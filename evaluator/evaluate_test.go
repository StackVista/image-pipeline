package main

import (
	"strings"
	"testing"
	"time"
)

const testImage = "quay.io/stackstate/kafka"

func newException(image, cve, expires, sourcePath string) Exception {
	return Exception{
		SchemaVersion: "1",
		Vulnerability: VulnRef{ID: cve, Severity: "HIGH"},
		Product:       ProductRef{Consumer: "docker-images", Image: image},
		Status:        "accepted_pending_upstream_fix",
		Reason:        "preserve_appco_provenance",
		Expires:       expires,
		Owner:         "@StackVista/observability-team",
		Statement:     "test",
		SourcePath:    sourcePath,
	}
}

func sevSet(severities ...string) map[string]bool {
	m := map[string]bool{}
	for _, s := range severities {
		m[strings.ToUpper(s)] = true
	}
	return m
}

func TestEvaluate_MatchUnexpired_Suppresses(t *testing.T) {
	findings := []Finding{
		{VulnerabilityID: "CVE-1", PackageName: "foo", Severity: "HIGH", SourceScanners: []string{"trivy"}},
	}
	exceptions := map[ExceptionKey]Exception{
		{Image: testImage, CVE: "CVE-1"}: newException(testImage, "CVE-1", "2099-01-01", "exceptions/test/CVE-1.yaml"),
	}
	out := Evaluate(testImage, findings, exceptions, sevSet("HIGH", "CRITICAL"))
	if len(out) != 1 {
		t.Fatalf("expected 1 decision; got %d", len(out))
	}
	if out[0].Suppressed == nil {
		t.Fatal("expected Suppressed; got nil")
	}
	if !strings.HasPrefix(out[0].Suppressed.Source, "exception/") {
		t.Errorf("Source = %q; want prefix exception/", out[0].Suppressed.Source)
	}
}

func TestEvaluate_NoMatch_Unmanaged(t *testing.T) {
	findings := []Finding{
		{VulnerabilityID: "CVE-99", PackageName: "foo", Severity: "CRITICAL", SourceScanners: []string{"trivy"}},
	}
	out := Evaluate(testImage, findings, map[ExceptionKey]Exception{}, sevSet("HIGH", "CRITICAL"))
	if len(out) != 1 {
		t.Fatalf("expected 1 decision; got %d", len(out))
	}
	if out[0].Suppressed != nil || out[0].Expired != nil {
		t.Errorf("expected no suppression and no expired; got %+v", out[0])
	}
}

func TestEvaluate_MatchExpired_FailsGate(t *testing.T) {
	findings := []Finding{
		{VulnerabilityID: "CVE-1", PackageName: "foo", Severity: "HIGH", SourceScanners: []string{"trivy"}},
	}
	yesterday := time.Now().UTC().Add(-48 * time.Hour).Format("2006-01-02")
	exceptions := map[ExceptionKey]Exception{
		{Image: testImage, CVE: "CVE-1"}: newException(testImage, "CVE-1", yesterday, "exceptions/test/CVE-1.yaml"),
	}
	out := Evaluate(testImage, findings, exceptions, sevSet("HIGH", "CRITICAL"))
	if len(out) != 1 {
		t.Fatalf("expected 1 decision; got %d", len(out))
	}
	if out[0].Expired == nil {
		t.Fatal("expected Expired; got nil")
	}
}

func TestEvaluate_BadDate_TreatedAsExpired(t *testing.T) {
	findings := []Finding{
		{VulnerabilityID: "CVE-1", PackageName: "foo", Severity: "HIGH", SourceScanners: []string{"trivy"}},
	}
	exceptions := map[ExceptionKey]Exception{
		{Image: testImage, CVE: "CVE-1"}: newException(testImage, "CVE-1", "not-a-date", "exceptions/test/CVE-1.yaml"),
	}
	out := Evaluate(testImage, findings, exceptions, sevSet("HIGH", "CRITICAL"))
	if out[0].Expired == nil {
		t.Fatalf("expected Expired (fail-closed on bad date); got Suppressed=%v", out[0].Suppressed)
	}
}

func TestEvaluate_BelowSeverity_Excluded(t *testing.T) {
	findings := []Finding{
		{VulnerabilityID: "CVE-1", PackageName: "foo", Severity: "MEDIUM", SourceScanners: []string{"trivy"}},
		{VulnerabilityID: "CVE-2", PackageName: "bar", Severity: "HIGH", SourceScanners: []string{"trivy"}},
	}
	out := Evaluate(testImage, findings, map[ExceptionKey]Exception{}, sevSet("HIGH", "CRITICAL"))
	if len(out) != 1 {
		t.Fatalf("expected 1 decision (MEDIUM filtered); got %d", len(out))
	}
	if out[0].Finding.VulnerabilityID != "CVE-2" {
		t.Errorf("kept wrong finding: %+v", out[0])
	}
}

func TestEvaluate_OtherImageException_DoesNotSuppress(t *testing.T) {
	// Same CVE, exception filed for a different image.
	// The current scan is on testImage; the kafka exception in the
	// fixture is for zookeeper. Should NOT suppress.
	findings := []Finding{
		{VulnerabilityID: "CVE-1", PackageName: "foo", Severity: "HIGH", SourceScanners: []string{"trivy"}},
	}
	exceptions := map[ExceptionKey]Exception{
		{Image: "quay.io/stackstate/zookeeper", CVE: "CVE-1"}: newException(
			"quay.io/stackstate/zookeeper", "CVE-1", "2099-01-01", "exceptions/test/zookeeper-CVE-1.yaml"),
	}
	out := Evaluate(testImage, findings, exceptions, sevSet("HIGH", "CRITICAL"))
	if len(out) != 1 {
		t.Fatalf("expected 1 decision; got %d", len(out))
	}
	if out[0].Suppressed != nil {
		t.Errorf("exception for a different image should not suppress; got Suppressed=%+v", out[0].Suppressed)
	}
	if out[0].Expired != nil {
		t.Errorf("exception for a different image should not register as expired; got Expired=%+v", out[0].Expired)
	}
}
