package grypevex

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrepareSkipsRejectedThirdPartyDocuments(t *testing.T) {
	cases := []struct {
		name   string
		change func(*advisory)
		reason string
	}{
		{"nested relationship", func(s *advisory) {
			s.ProductTree.Relationships[0].Product = s.ProductTree.Relationships[0].FullProductName.ID
		}, "nested CSAF relationship"},
		{"CPE helper", func(s *advisory) {
			s.ProductTree.Branches[0].Branches[1].Product.Helper["cpe"] = json.RawMessage(`"cpe:/a:example:jackson:2.22.0"`)
		}, "cannot be preserved"},
		{"affected without remediation", func(s *advisory) {
			id := s.ProductTree.Relationships[0].FullProductName.ID
			s.Vulnerabilities[0].ProductStatus = map[string][]string{"known_affected": {id}}
			s.Vulnerabilities[0].Remediations = nil
		}, "no affected action statement"},
	}
	for _, tc := range cases {
		for _, permissive := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/skip=%t", tc.name, permissive), func(t *testing.T) {
				root := t.TempDir()
				config := filepath.Join(root, "repository.yaml")
				write(t, config, []byte(fmt.Sprintf("repositories:\n  - name: rancher\n    enabled: true\n    skip_invalid_documents: %t\n", permissive)))
				version := filepath.Join(root, "cache/rancher/0.1")
				write(t, filepath.Join(version, "index.json"), []byte(`{"packages":[{"format":"csaf","location":"good.json"},{"format":"csaf","location":"bad.json"}]}`))
				write(t, filepath.Join(version, "good.json"), fixture(t))
				var source advisory
				if err := json.Unmarshal(fixture(t), &source); err != nil {
					t.Fatal(err)
				}
				tc.change(&source)
				bad, err := json.Marshal(source)
				if err != nil {
					t.Fatal(err)
				}
				write(t, filepath.Join(version, "bad.json"), bad)
				result, problems := Prepare(filepath.Join(root, "cache"), config, filepath.Join(root, "converted"))
				if len(result.Documents) != 1 || result.CSAF != 1 {
					t.Fatalf("rejected document leaked into output: %+v", result)
				}
				diagnostics := problems
				if permissive {
					if len(problems) != 0 {
						t.Fatal(problems)
					}
					diagnostics = result.Warnings
				} else if len(result.Warnings) != 0 {
					t.Fatal("strict repository produced a warning instead of an error")
				}
				if len(diagnostics) != 1 || !strings.Contains(diagnostics[0].Error(), tc.reason) ||
					!strings.Contains(diagnostics[0].Error(), "bad.json") {
					t.Fatalf("missing file/reason diagnostic: %v", diagnostics)
				}
			})
		}
	}
}

func TestPreparePermissiveRepositoryStillRequiresUsableFeed(t *testing.T) {
	for _, failure := range []string{"missing index", "invalid index", "empty index", "missing document", "unsafe path", "all rejected"} {
		t.Run(failure, func(t *testing.T) {
			root := t.TempDir()
			config := filepath.Join(root, "repository.yaml")
			write(t, config, []byte("repositories:\n  - name: rancher\n    enabled: true\n    skip_invalid_documents: true\n  - name: stackvista\n    enabled: true\n"))
			local := filepath.Join(root, "cache/stackvista/0.1")
			write(t, filepath.Join(local, "index.json"), []byte(`{"packages":[{"format":"openvex","location":"good.json"}]}`))
			write(t, filepath.Join(local, "good.json"), []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","statements":[]}`))
			version := filepath.Join(root, "cache/rancher/0.1")
			switch failure {
			case "invalid index":
				write(t, filepath.Join(version, "index.json"), []byte("{"))
			case "empty index":
				write(t, filepath.Join(version, "index.json"), []byte(`{"packages":[]}`))
			case "missing document":
				write(t, filepath.Join(version, "index.json"), []byte(`{"packages":[{"format":"csaf","location":"missing.json"}]}`))
			case "unsafe path":
				write(t, filepath.Join(version, "index.json"), []byte(`{"packages":[{"format":"csaf","location":"../outside.json"}]}`))
			case "all rejected":
				write(t, filepath.Join(version, "index.json"), []byte(`{"packages":[{"format":"csaf","location":"bad.json"}]}`))
				write(t, filepath.Join(version, "bad.json"), []byte("{}"))
			}
			result, problems := Prepare(filepath.Join(root, "cache"), config, filepath.Join(root, "converted"))
			if len(problems) == 0 || len(result.Documents) != 1 {
				t.Fatalf("incomplete third-party feed was accepted: %+v %v", result, problems)
			}
		})
	}
}

func write(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareUsesEnabledRepositoryIndexes(t *testing.T) {
	root := t.TempDir()
	cache := filepath.Join(root, "cache")
	config := filepath.Join(root, "repository.yaml")
	write(t, config, []byte("repositories:\n  - name: rancher\n    enabled: true\n  - name: stackvista\n    enabled: true\n  - name: disabled\n    enabled: false\n"))
	rancher := filepath.Join(cache, "rancher", "0.1")
	stackvista := filepath.Join(cache, "stackvista", "0.1")
	write(t, filepath.Join(rancher, "index.json"), []byte(`{"packages":[{"format":"csaf","location":"pkg/zookeeper/scan.vex.json"}]}`))
	write(t, filepath.Join(rancher, "pkg/zookeeper/scan.vex.json"), fixture(t))
	write(t, filepath.Join(rancher, "reports/rancher.openvex.json.gz"), []byte("unusable deprecated export"))
	write(t, filepath.Join(stackvista, "index.json"), []byte(`{"packages":[{"location":"pkg/local/arbitrary-name.json"}]}`))
	original := []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","statements":[]}`)
	originalPath := filepath.Join(stackvista, "pkg/local/arbitrary-name.json")
	write(t, originalPath, original)
	result, problems := Prepare(cache, config, filepath.Join(root, "converted"))
	if len(problems) != 0 {
		t.Fatal(problems)
	}
	if len(result.Documents) != 2 || result.CSAF != 1 || result.OpenVEX != 1 {
		t.Fatalf("unexpected document inventory: %+v", result)
	}
	converted, err := os.ReadFile(result.Documents[0])
	if err != nil {
		t.Fatal(err)
	}
	if decoded(t, converted).Statements[0].Products[0].ID != "pkg:oci/zookeeper?repository_url=quay.io/stackstate/zookeeper" {
		t.Fatal("CSAF scope changed during repository preparation")
	}
	if result.Documents[1] != originalPath {
		t.Fatal("OpenVEX document was not passed through")
	}
	unchanged, err := os.ReadFile(originalPath)
	if err != nil || string(unchanged) != string(original) {
		t.Fatal("existing OpenVEX document was changed")
	}
}

func TestPrepareSupportsNestedArchiveRoot(t *testing.T) {
	root := t.TempDir()
	config := filepath.Join(root, "repository.yaml")
	write(t, config, []byte("repositories:\n  - name: rancher\n    enabled: true\n"))
	version := filepath.Join(root, "cache/rancher/0.1/vexhub-main")
	write(t, filepath.Join(version, "index.json"), []byte(`{"packages":[{"format":"csaf","location":"pkg/scan.vex.json"}]}`))
	write(t, filepath.Join(version, "pkg/scan.vex.json"), fixture(t))
	result, problems := Prepare(filepath.Join(root, "cache"), config, filepath.Join(root, "converted"))
	if len(problems) != 0 || result.CSAF != 1 {
		t.Fatalf("nested archive root not supported: %+v %v", result, problems)
	}
}

func TestDocumentPathRejectsEscapeAndListInjection(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "repo")
	write(t, filepath.Join(root, "safe.json"), []byte("{}"))
	write(t, filepath.Join(parent, "outside.json"), []byte("{}"))
	if err := os.Symlink(filepath.Join(parent, "outside.json"), filepath.Join(root, "escape.json")); err != nil {
		t.Fatal(err)
	}
	for _, location := range []string{
		"../outside.json", "escape.json", "/outside.json", "safe.json\nanother.json", `..\outside.json`,
	} {
		if _, err := documentPath(root, location); err == nil {
			t.Errorf("accepted unsafe document location %q", location)
		}
	}
}

func TestPrepareReportsMissingRepositoryAndUnknownFormat(t *testing.T) {
	root := t.TempDir()
	config := filepath.Join(root, "repository.yaml")
	write(t, config, []byte("repositories:\n  - name: missing\n    enabled: true\n  - name: unsupported\n    enabled: true\n"))
	version := filepath.Join(root, "cache/unsupported/0.1")
	write(t, filepath.Join(version, "index.json"), []byte(`{"packages":[{"format":"unsupported","location":"doc.json"}]}`))
	write(t, filepath.Join(version, "doc.json"), []byte("{}"))
	result, problems := Prepare(filepath.Join(root, "cache"), config, filepath.Join(root, "converted"))
	if len(result.Documents) != 0 || len(problems) < 2 {
		t.Fatalf("missing coverage was accepted: %+v %v", result, problems)
	}
	var messages []string
	for _, problem := range problems {
		messages = append(messages, problem.Error())
	}
	if !strings.Contains(strings.Join(messages, "\n"), "unsupported VEX format") {
		t.Fatal("unsupported format was not reported")
	}
}

func TestDocumentPathRejectsLineBreaksInSymlinkTarget(t *testing.T) {
	root := t.TempDir()
	for i, target := range []string{"safe.json\ninjected.json", "safe.json\rinjected.json"} {
		path := filepath.Join(root, target)
		write(t, path, []byte("{}"))
		location := fmt.Sprintf("document-%d.json", i)
		if err := os.Symlink(path, filepath.Join(root, location)); err != nil {
			t.Fatal(err)
		}
		if _, err := documentPath(root, location); err == nil {
			t.Fatal("accepted a resolved path that creates extra document-list lines")
		}
	}
}

func TestPrepareRejectsLineBreaksInConvertedPath(t *testing.T) {
	root := t.TempDir()
	config := filepath.Join(root, "repository.yaml")
	write(t, config, []byte("repositories:\n  - name: rancher\n    enabled: true\n"))
	version := filepath.Join(root, "cache/rancher/0.1")
	write(t, filepath.Join(version, "index.json"), []byte(`{"packages":[{"format":"csaf","location":"doc.json"}]}`))
	write(t, filepath.Join(version, "doc.json"), fixture(t))
	result, problems := Prepare(filepath.Join(root, "cache"), config, filepath.Join(root, "output\ninjected"))
	if len(result.Documents) != 0 || result.CSAF != 0 || len(problems) == 0 {
		t.Fatalf("accepted a converted path that creates extra document-list lines: %+v %v", result, problems)
	}
}
