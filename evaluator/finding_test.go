package main

import (
	"os"
	"reflect"
	"testing"
)

func TestDedupeFindings_MergesIdentical(t *testing.T) {
	in := []Finding{
		{VulnerabilityID: "CVE-1", PackageName: "foo", PackageVersion: "1.0", Severity: "HIGH", SourceScanners: []string{"trivy"}},
		{VulnerabilityID: "CVE-1", PackageName: "foo", PackageVersion: "1.0", Severity: "HIGH", SourceScanners: []string{"grype"}},
	}
	out := DedupeFindings(in)
	if len(out) != 1 {
		t.Fatalf("expected 1 entry; got %d", len(out))
	}
	want := []string{"grype", "trivy"}
	if !reflect.DeepEqual(out[0].SourceScanners, want) {
		t.Errorf("SourceScanners = %v; want %v", out[0].SourceScanners, want)
	}
}

func TestDedupeFindings_KeepsDistinct(t *testing.T) {
	in := []Finding{
		{VulnerabilityID: "CVE-1", PackageName: "foo", PackageVersion: "1.0", SourceScanners: []string{"trivy"}},
		{VulnerabilityID: "CVE-2", PackageName: "foo", PackageVersion: "1.0", SourceScanners: []string{"trivy"}},
		{VulnerabilityID: "CVE-1", PackageName: "bar", PackageVersion: "1.0", SourceScanners: []string{"trivy"}},
		{VulnerabilityID: "CVE-1", PackageName: "foo", PackageVersion: "2.0", SourceScanners: []string{"trivy"}},
	}
	out := DedupeFindings(in)
	if len(out) != 4 {
		t.Errorf("expected 4 distinct entries; got %d", len(out))
	}
}

func TestDedupeFindings_Sorted(t *testing.T) {
	in := []Finding{
		{VulnerabilityID: "CVE-3", PackageName: "z", PackageVersion: "1.0", SourceScanners: []string{"trivy"}},
		{VulnerabilityID: "CVE-1", PackageName: "a", PackageVersion: "1.0", SourceScanners: []string{"trivy"}},
		{VulnerabilityID: "CVE-2", PackageName: "m", PackageVersion: "1.0", SourceScanners: []string{"trivy"}},
	}
	out := DedupeFindings(in)
	got := []string{out[0].VulnerabilityID, out[1].VulnerabilityID, out[2].VulnerabilityID}
	want := []string{"CVE-1", "CVE-2", "CVE-3"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("dedup order = %v; want %v", got, want)
	}
}

func TestMergeStrings_DedupAndSort(t *testing.T) {
	got := mergeStrings([]string{"trivy", "grype"}, []string{"grype", "snyk"})
	want := []string{"grype", "snyk", "trivy"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("mergeStrings = %v; want %v", got, want)
	}
}

// TestDedupeFindings_UnionsSlices covers the case where two scanners
// report the same finding but disagree on auxiliary slice fields
// (FixedVersions, Paths). The deduped Finding must carry the union
// — losing one scanner's data would be a downgrade.
func TestDedupeFindings_UnionsSlices(t *testing.T) {
	in := []Finding{
		{
			VulnerabilityID: "CVE-1", PackageName: "foo", PackageVersion: "1.0",
			SourceScanners: []string{"trivy"},
			FixedVersions:  []string{"1.0.1"},
			Paths:          []string{"/opt/foo/lib"},
		},
		{
			VulnerabilityID: "CVE-1", PackageName: "foo", PackageVersion: "1.0",
			SourceScanners: []string{"grype"},
			FixedVersions:  []string{"1.0.1", "1.1.0"},
			Paths:          []string{"/opt/foo/lib", "/usr/lib/foo"},
		},
	}
	out := DedupeFindings(in)
	if len(out) != 1 {
		t.Fatalf("expected 1 entry; got %d", len(out))
	}
	if want := []string{"1.0.1", "1.1.0"}; !reflect.DeepEqual(out[0].FixedVersions, want) {
		t.Errorf("FixedVersions = %v; want %v (union)", out[0].FixedVersions, want)
	}
	if want := []string{"/opt/foo/lib", "/usr/lib/foo"}; !reflect.DeepEqual(out[0].Paths, want) {
		t.Errorf("Paths = %v; want %v (union)", out[0].Paths, want)
	}
}

// TestDedupeFindings_AcrossScannerFixtures is the cross-adapter
// integration test: parse both fixtures and verify the dedup story
// works end-to-end on realistic data.
func TestDedupeFindings_AcrossScannerFixtures(t *testing.T) {
	tf, err := os.Open("testdata/trivy-kafka-fixture.json")
	if err != nil {
		t.Fatalf("open trivy fixture: %v", err)
	}
	defer tf.Close()
	trivyFindings, err := TrivyScanner{}.Parse(tf)
	if err != nil {
		t.Fatalf("trivy Parse: %v", err)
	}

	gf, err := os.Open("testdata/grype-kafka-fixture.json")
	if err != nil {
		t.Fatalf("open grype fixture: %v", err)
	}
	defer gf.Close()
	grypeFindings, err := GrypeScanner{}.Parse(gf)
	if err != nil {
		t.Fatalf("grype Parse: %v", err)
	}

	merged := DedupeFindings(append(trivyFindings, grypeFindings...))
	if len(merged) != 3 {
		t.Fatalf("expected 3 deduped findings; got %d", len(merged))
	}
	for _, f := range merged {
		if want := []string{"grype", "trivy"}; !reflect.DeepEqual(f.SourceScanners, want) {
			t.Errorf("CVE %s: SourceScanners = %v; want %v", f.VulnerabilityID, f.SourceScanners, want)
		}
		if len(f.Paths) != 1 {
			t.Errorf("CVE %s: Paths = %v; want 1 entry (fixtures use matching paths)", f.VulnerabilityID, f.Paths)
		}
	}
}
