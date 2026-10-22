package grypevex

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
