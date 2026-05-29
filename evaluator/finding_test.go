package main

import (
	"os"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMergeStrings(t *testing.T) {
	require.Equal(t, []string{"grype", "snyk", "trivy"}, mergeStrings([]string{"trivy", "grype"}, []string{"grype", "snyk"}))
}

func TestDedupeFindings(t *testing.T) {
	tests := []struct {
		name string
		in   []Finding
		want []Finding
	}{
		{
			name: "merges_identical_findings_from_different_scanners",
			in: []Finding{
				{
					VulnerabilityID: "CVE-1",
					PackagePURL:     "pkg:generic/foo@1.0",
					SourceScanners:  []string{"trivy"},
				},
				{
					VulnerabilityID: "CVE-1",
					PackagePURL:     "pkg:generic/foo@1.0",
					SourceScanners:  []string{"grype"},
				},
			},
			want: []Finding{
				{
					VulnerabilityID: "CVE-1",
					PackagePURL:     "pkg:generic/foo@1.0",
					SourceScanners:  []string{"grype", "trivy"},
				},
			},
		},
		{
			name: "keeps_distinct_findings_separate",
			in: []Finding{
				{VulnerabilityID: "CVE-1", PackagePURL: "pkg:generic/foo@1.0", SourceScanners: []string{"trivy"}},
				{VulnerabilityID: "CVE-1", PackagePURL: "pkg:different_generic/foo@1.0", SourceScanners: []string{"grype"}},
				{VulnerabilityID: "CVE-2", PackagePURL: "pkg:generic/foo@1.0", SourceScanners: []string{"grype"}},
			},
			want: []Finding{
				{VulnerabilityID: "CVE-1", PackagePURL: "pkg:different_generic/foo@1.0", SourceScanners: []string{"grype"}},
				{VulnerabilityID: "CVE-1", PackagePURL: "pkg:generic/foo@1.0", SourceScanners: []string{"trivy"}},
				{VulnerabilityID: "CVE-2", PackagePURL: "pkg:generic/foo@1.0", SourceScanners: []string{"grype"}},
			},
		},
		{
			name: "returns_deterministic_sort_order",
			in: []Finding{
				{VulnerabilityID: "CVE-3", PackagePURL: "pkg:generic/foo@2.0", SourceScanners: []string{"trivy"}},
				{VulnerabilityID: "CVE-1", PackagePURL: "pkg:generic/foo@1.0", SourceScanners: []string{"trivy"}},
			},
			want: []Finding{
				{VulnerabilityID: "CVE-1", PackagePURL: "pkg:generic/foo@1.0", SourceScanners: []string{"trivy"}},
				{VulnerabilityID: "CVE-3", PackagePURL: "pkg:generic/foo@2.0", SourceScanners: []string{"trivy"}},
			},
		},
		{
			name: "unions_slice_fields_across_duplicates",
			in: []Finding{
				{
					VulnerabilityID: "CVE-1",
					PackagePURL:     "pkg:generic/foo@1.0",
					SourceScanners:  []string{"trivy"},
					FixedVersions:   []string{"1.0.1"},
					Paths:           []string{"/opt/foo/lib"},
				},
				{
					VulnerabilityID: "CVE-1",
					PackagePURL:     "pkg:generic/foo@1.0",
					SourceScanners:  []string{"grype"},
					FixedVersions:   []string{"1.0.1", "1.1.0"},
					Paths:           []string{"/opt/foo/lib", "/usr/lib/foo"},
				},
			},
			want: []Finding{
				{
					VulnerabilityID: "CVE-1",
					PackagePURL:     "pkg:generic/foo@1.0",
					SourceScanners:  []string{"grype", "trivy"},
					FixedVersions:   []string{"1.0.1", "1.1.0"},
					Paths:           []string{"/opt/foo/lib", "/usr/lib/foo"},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := DedupeFindings(tt.in)
			require.Equal(t, tt.want, out)
		})
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
