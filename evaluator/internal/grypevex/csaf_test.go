package grypevex

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func fixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/zookeeper.csaf.json")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func decoded(t *testing.T, data []byte) openVEX {
	t.Helper()
	var result openVEX
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestConvertPreservesImageAndComponentScope(t *testing.T) {
	data, err := Convert(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	result := decoded(t, data)
	if len(result.Statements) != 1 {
		t.Fatalf("expected one CVE statement, got %d", len(result.Statements))
	}
	s := result.Statements[0]
	if s.Vulnerability.Name != "CVE-2026-54515" || s.Status != "not_affected" ||
		s.Justification != "vulnerable_code_not_in_execute_path" {
		t.Fatalf("lost vulnerability assessment: %+v", s)
	}
	if len(s.Products) != 1 || s.Products[0].ID != "pkg:oci/zookeeper?repository_url=quay.io/stackstate/zookeeper" {
		t.Fatalf("lost image scope: %+v", s.Products)
	}
	components := s.Products[0].Subcomponents
	if len(components) != 1 || components[0].ID != "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.22.0" {
		t.Fatalf("lost component scope: %+v", components)
	}
	if result.Timestamp != "2026-10-21T04:27:47Z" || result.Version != 2 {
		t.Fatalf("changed source revision: %+v", result)
	}
	if strings.Contains(string(data), "product_identification_helper") || strings.Contains(string(data), "cvss_v3") {
		t.Fatal("CSAF-only fields leaked into the OpenVEX compatibility document")
	}
}

func TestConvertSupportedRelationships(t *testing.T) {
	for _, category := range []string{"default_component_of", "installed_on", "installed_with"} {
		t.Run(category, func(t *testing.T) {
			var source advisory
			if err := json.Unmarshal(fixture(t), &source); err != nil {
				t.Fatal(err)
			}
			source.ProductTree.Relationships[0].Category = category
			data, err := json.Marshal(source)
			if err != nil {
				t.Fatal(err)
			}
			converted, err := Convert(data)
			if err != nil {
				t.Fatal(err)
			}
			p := decoded(t, converted).Statements[0].Products[0]
			if p.ID != "pkg:oci/zookeeper?repository_url=quay.io/stackstate/zookeeper" ||
				len(p.Subcomponents) != 1 {
				t.Fatalf("relationship %s lost its parent: %+v", category, p)
			}
		})
	}
}

func TestConvertRejectsUnresolvableOrAmbiguousScope(t *testing.T) {
	tests := []struct {
		name   string
		change func(*advisory)
	}{
		{"unknown parent", func(s *advisory) { s.ProductTree.Relationships[0].Parent = "unknown" }},
		{"unknown component", func(s *advisory) { s.ProductTree.Relationships[0].Product = "unknown" }},
		{"unsupported relationship", func(s *advisory) { s.ProductTree.Relationships[0].Category = "optional_component_of" }},
		{"relationship cycle", func(s *advisory) { s.ProductTree.Relationships[0].Product = "jackson-in-zookeeper" }},
		{"missing component purl", func(s *advisory) { delete(s.ProductTree.Branches[0].Branches[1].Product.Helper, "purl") }},
		{"conflicting statuses", func(s *advisory) {
			s.Vulnerabilities[0].ProductStatus["known_affected"] = []string{"jackson-in-zookeeper"}
		}},
		{"missing justification", func(s *advisory) { s.Vulnerabilities[0].Flags = nil }},
		{"missing source timestamp", func(s *advisory) { s.Document.Tracking.CurrentReleaseDate = "" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var source advisory
			if err := json.Unmarshal(fixture(t), &source); err != nil {
				t.Fatal(err)
			}
			test.change(&source)
			data, err := json.Marshal(source)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Convert(data); err == nil {
				t.Fatal("conversion accepted an assessment whose scope or evidence was lost")
			}
		})
	}
}

func TestConvertPackageAssessmentAndImpactStatement(t *testing.T) {
	var source advisory
	if err := json.Unmarshal(fixture(t), &source); err != nil {
		t.Fatal(err)
	}
	source.Vulnerabilities[0].ProductStatus["known_not_affected"] = []string{"jackson"}
	source.Vulnerabilities[0].Flags = nil
	source.Vulnerabilities[0].Threats = []annotation{{
		Category: "impact", Details: "The affected function is not called.", ProductIDs: []string{"jackson"},
	}}
	data, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	converted, err := Convert(data)
	if err != nil {
		t.Fatal(err)
	}
	s := decoded(t, converted).Statements[0]
	if s.Products[0].ID != "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.22.0" ||
		len(s.Products[0].Subcomponents) != 0 || s.ImpactStatement != "The affected function is not called." {
		t.Fatalf("changed package assessment: %+v", s)
	}
}

func TestConvertPreservesVulnerabilityIdentifiers(t *testing.T) {
	tests := []struct {
		name string
		cve  string
		ids  []identifier
		want []string
	}{
		{"GHSA without CVE", "", []identifier{{Text: "GHSA-5jmj-h7xm-6q6v"}}, []string{"GHSA-5jmj-h7xm-6q6v"}},
		{"GO without CVE", "", []identifier{{Text: "GO-2026-5932"}}, []string{"GO-2026-5932"}},
		{"CVE in ids", "", []identifier{{Text: "CVE-2026-54515"}}, []string{"CVE-2026-54515"}},
		{"aliases", "CVE-2026-54515", []identifier{
			{Text: "CVE-2026-54515"}, {Text: "GHSA-5jmj-h7xm-6q6v"}, {Text: "GHSA-5jmj-h7xm-6q6v"},
		}, []string{"CVE-2026-54515", "GHSA-5jmj-h7xm-6q6v"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var source advisory
			if err := json.Unmarshal(fixture(t), &source); err != nil {
				t.Fatal(err)
			}
			source.Vulnerabilities[0].CVE = test.cve
			source.Vulnerabilities[0].IDs = test.ids
			raw, err := json.Marshal(source)
			if err != nil {
				t.Fatal(err)
			}
			converted, err := Convert(raw)
			if err != nil {
				t.Fatal(err)
			}
			statements := decoded(t, converted).Statements
			if len(statements) != len(test.want) {
				t.Fatalf("expected identifiers %v, got %+v", test.want, statements)
			}
			for i, s := range statements {
				if s.Vulnerability.Name != test.want[i] || s.Status != "not_affected" ||
					s.Justification != "vulnerable_code_not_in_execute_path" ||
					s.Products[0].ID != "pkg:oci/zookeeper?repository_url=quay.io/stackstate/zookeeper" ||
					len(s.Products[0].Subcomponents) != 1 ||
					s.Products[0].Subcomponents[0].ID != "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.22.0" {
					t.Fatalf("identifier %s lost its assessment or scope: %+v", test.want[i], s)
				}
			}
		})
	}
}

func TestConvertPreservesAllSupportedDispositions(t *testing.T) {
	for csaf, openvex := range map[string]string{
		"known_not_affected":  "not_affected",
		"known_affected":      "affected",
		"fixed":               "fixed",
		"under_investigation": "under_investigation",
	} {
		t.Run(csaf, func(t *testing.T) {
			var source advisory
			if err := json.Unmarshal(fixture(t), &source); err != nil {
				t.Fatal(err)
			}
			source.Vulnerabilities[0].ProductStatus = map[string][]string{csaf: {"jackson-in-zookeeper"}}
			if csaf == "known_affected" {
				source.Vulnerabilities[0].Remediations = []annotation{{
					Category: "vendor_fix", Details: "Upgrade Jackson.", ProductIDs: []string{"jackson-in-zookeeper"},
				}}
			}
			raw, err := json.Marshal(source)
			if err != nil {
				t.Fatal(err)
			}
			converted, err := Convert(raw)
			if err != nil {
				t.Fatal(err)
			}
			s := decoded(t, converted).Statements[0]
			if s.Status != openvex || len(s.Products[0].Subcomponents) != 1 {
				t.Fatalf("lost %s assessment: %+v", csaf, s)
			}
		})
	}
}
