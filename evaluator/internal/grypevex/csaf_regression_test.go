package grypevex

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	vex "github.com/openvex/go-vex/pkg/vex"
)

func sourceFixture(t *testing.T, name string) advisory {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name+".csaf.json"))
	if err != nil {
		t.Fatal(err)
	}
	var source advisory
	if err := json.Unmarshal(data, &source); err != nil {
		t.Fatal(err)
	}
	return source
}

func convertSource(t *testing.T, source advisory) ([]byte, error) {
	t.Helper()
	raw, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	return Convert(raw)
}

func TestConvertRejectsRelationshipIdentificationHelpers(t *testing.T) {
	for _, helper := range []map[string]json.RawMessage{
		{"purl": json.RawMessage(`"pkg:oci/zookeeper@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa?repository_url=quay.io%2Fstackstate%2Fzookeeper"`)},
		{"cpe": json.RawMessage(`"cpe:2.3:a:apache:zookeeper:3.9.5:*:*:*:*:*:*:*"`)},
	} {
		source := sourceFixture(t, "relationship-identity")
		source.ProductTree.Relationships[0].FullProductName.Helper = helper
		if _, err := convertSource(t, source); err == nil || !strings.Contains(err.Error(), "cannot be preserved") {
			t.Fatalf("relationship identity was silently discarded: %v", err)
		}
	}
}

func TestConvertRejectsAdditionalProductIdentificationMethods(t *testing.T) {
	source := sourceFixture(t, "zookeeper")
	source.ProductTree.Branches[0].Branches[0].Product.Helper["cpe"] =
		json.RawMessage(`"cpe:2.3:a:apache:zookeeper:3.9.4:*:*:*:*:*:*:*"`)
	if _, err := convertSource(t, source); err == nil || !strings.Contains(err.Error(), "cannot be preserved") {
		t.Fatalf("discarded an additional identifier on the image product: %v", err)
	}
}

func TestConvertResolvesGroupedAnnotations(t *testing.T) {
	for _, kind := range []string{"flag", "impact", "remediation"} {
		t.Run(kind, func(t *testing.T) {
			source := sourceFixture(t, "product-groups")
			switch kind {
			case "impact":
				source.Vulnerabilities[0].Flags = nil
				source.Vulnerabilities[0].Threats = []annotation{{
					Category: "impact", Details: "The affected function is not called.", GroupIDs: []string{"G"},
				}}
			case "remediation":
				source.Vulnerabilities[0].ProductStatus = map[string][]string{"known_affected": {"C", "C2"}}
				source.Vulnerabilities[0].Flags = nil
				source.Vulnerabilities[0].Remediations = []annotation{{
					Category: "vendor_fix", Details: "Upgrade both images.", GroupIDs: []string{"G"},
				}}
			}
			converted, err := convertSource(t, source)
			if err != nil {
				t.Fatal(err)
			}
			statements := decoded(t, converted).Statements
			if len(statements) != 2 {
				t.Fatalf("lost a grouped assessment: %+v", statements)
			}
			for _, s := range statements {
				if len(s.Products) != 1 || len(s.Products[0].Subcomponents) != 1 ||
					s.Products[0].Subcomponents[0].ID != "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.22.0" {
					t.Fatalf("group changed component scope: %+v", s)
				}
				switch kind {
				case "flag":
					if s.Justification != "vulnerable_code_not_in_execute_path" {
						t.Fatalf("lost grouped justification: %+v", s)
					}
				case "impact":
					if s.ImpactStatement != "The affected function is not called." {
						t.Fatalf("lost grouped impact statement: %+v", s)
					}
				case "remediation":
					if s.Status != "affected" || s.ActionStatement != "Upgrade both images." {
						t.Fatalf("lost grouped action statement: %+v", s)
					}
				}
			}
			if statements[0].Products[0].ID == statements[1].Products[0].ID {
				t.Fatal("group lost distinct image scopes")
			}
		})
	}
}

func TestConvertRejectsInvalidOrUnrelatedGroups(t *testing.T) {
	for _, kind := range []string{"unknown", "duplicate", "unrelated"} {
		t.Run(kind, func(t *testing.T) {
			source := sourceFixture(t, "product-groups")
			switch kind {
			case "unknown":
				source.Vulnerabilities[0].Flags[0].GroupIDs = []string{"missing"}
			case "duplicate":
				source.ProductTree.Groups = append(source.ProductTree.Groups, source.ProductTree.Groups[0])
			case "unrelated":
				source.Vulnerabilities[0].ProductStatus["known_not_affected"] = []string{"C"}
				source.ProductTree.Groups[0].ProductIDs = []string{"C2", "B2"}
			}
			if _, err := convertSource(t, source); err == nil {
				t.Fatal("accepted an unknown group or justification for a different scope")
			}
		})
	}
}

func TestConvertPreservesAffectedRemediations(t *testing.T) {
	source := sourceFixture(t, "affected-remediation")
	source.Vulnerabilities[0].Remediations[0].Date = "2026-10-21T11:00:00+02:00"
	source.Vulnerabilities[0].Remediations = append(source.Vulnerabilities[0].Remediations,
		annotation{
			Category: "workaround", Details: "Disable the affected feature.",
			ProductIDs: []string{"C"}, Date: "2026-10-21T12:00:00.123+02:00",
		},
		annotation{Category: "vendor_fix", Details: "An unrelated action.", ProductIDs: []string{"B"}},
	)
	converted, err := convertSource(t, source)
	if err != nil {
		t.Fatal(err)
	}
	s := decoded(t, converted).Statements[0]
	if s.Status != "affected" || s.ActionStatement != "Upgrade Jackson.\n\nDisable the affected feature." ||
		s.ActionTimestamp != "2026-10-21T10:00:00.123Z" {
		t.Fatalf("lost remediation text, scope or date: %+v", s)
	}
}

func TestConvertRejectsAffectedWithoutUsableRemediation(t *testing.T) {
	for _, kind := range []string{"missing", "unrelated", "invalid date"} {
		t.Run(kind, func(t *testing.T) {
			source := sourceFixture(t, "affected-remediation")
			switch kind {
			case "missing":
				source.Vulnerabilities[0].Remediations = nil
			case "unrelated":
				source.Vulnerabilities[0].Remediations[0].ProductIDs = []string{"B"}
			case "invalid date":
				source.Vulnerabilities[0].Remediations[0].Date = "not-a-date"
			}
			if _, err := convertSource(t, source); err == nil {
				t.Fatal("accepted an affected assessment without a usable scoped action")
			}
		})
	}
}

func TestConvertRejectsConflictingResolvedScopes(t *testing.T) {
	for _, alternate := range []string{
		"pkg:oci/zookeeper?repository_url=quay.io%2Fstackstate%2Fzookeeper",
		"pkg:oci/zookeeper?repository_url=quay.io/stackstate/zookeeper",
	} {
		source := sourceFixture(t, "conflicting-scope")
		parent := source.ProductTree.FullProductNames[1]
		parent.ID = "B2"
		encoded, err := json.Marshal(alternate)
		if err != nil {
			t.Fatal(err)
		}
		parent.Helper = map[string]json.RawMessage{"purl": encoded}
		source.ProductTree.FullProductNames = append(source.ProductTree.FullProductNames, parent)
		source.ProductTree.Relationships[1].Parent = "B2"
		if _, err := convertSource(t, source); err == nil || !strings.Contains(err.Error(), "conflicting CSAF statuses") {
			t.Fatalf("accepted contradictory assessments of equivalent PURLs: %v", err)
		}
	}
}

func TestConvertOutputPassesOpenVEXStatementValidation(t *testing.T) {
	for _, name := range []string{"zookeeper", "product-groups", "affected-remediation", "fixed", "under_investigation"} {
		t.Run(name, func(t *testing.T) {
			fixtureName := name
			if name == "fixed" || name == "under_investigation" {
				fixtureName = "zookeeper"
			}
			source := sourceFixture(t, fixtureName)
			if name == "fixed" || name == "under_investigation" {
				source.Vulnerabilities[0].ProductStatus = map[string][]string{
					name: source.Vulnerabilities[0].ProductStatus["known_not_affected"],
				}
			}
			converted, err := convertSource(t, source)
			if err != nil {
				t.Fatal(err)
			}
			document, err := vex.Parse(converted)
			if err != nil {
				t.Fatal(err)
			}
			if len(document.Statements) == 0 {
				t.Fatal("no statements were generated")
			}
			for _, s := range document.Statements {
				if err := s.Validate(); err != nil {
					t.Fatalf("invalid generated OpenVEX statement: %v", err)
				}
			}
		})
	}
}
