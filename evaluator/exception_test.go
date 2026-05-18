package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const validExceptionYAML = `schema_version: "1"
vulnerability:
  id: CVE-2026-2332
  severity: HIGH
product:
  consumer: docker-images
  image: quay.io/stackstate/kafka
component:
  purl: pkg:maven/org.eclipse.jetty/jetty-http@9.4.57
status: accepted_pending_upstream_fix
reason: preserve_appco_provenance
expires: 2099-01-01
owner: "@StackVista/observability-team"
statement: test
`

// renderException is a tiny templater for tests: rebuilds the YAML
// body with overridden image and CVE.
func renderException(image, cve string) string {
	body := strings.Replace(validExceptionYAML, "quay.io/stackstate/kafka", image, 1)
	return strings.Replace(body, "CVE-2026-2332", cve, 1)
}

func writeException(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func createDirectory(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		writeException(t, dir, name, body)
	}
	return dir
}

func TestLoadExceptions(t *testing.T) {
	tests := []struct {
		name        string
		directory   string
		expectedKey []ExceptionKey
		// if -1 it means we expect an error
		wantLen int
	}{
		{
			// empty directory means no exceptions
			name:      "no exceptions",
			directory: "",
		},
		{
			name:      "directory doesn't exist",
			directory: "/zxydsds/d",
			wantLen:   -1,
		},
		{
			name: "single",
			directory: createDirectory(t, map[string]string{
				"kafka/CVE-2026-2332.yaml": validExceptionYAML,
			}),
			wantLen:     1,
			expectedKey: []ExceptionKey{{Image: "quay.io/stackstate/kafka", CVE: "CVE-2026-2332"}},
		},
		{
			name: "same cve different images allowed",
			directory: createDirectory(t, map[string]string{
				"kafka/CVE-2026-2332.yaml":     renderException("quay.io/stackstate/kafka", "CVE-2026-2332"),
				"zookeeper/CVE-2026-2332.yaml": renderException("quay.io/stackstate/zookeeper", "CVE-2026-2332"),
			}),
			wantLen: 2,
		},
		{
			name: "duplicate image cve errors",
			directory: createDirectory(t, map[string]string{
				"kafka/CVE-2026-2332.yaml": validExceptionYAML,
				"kafka/duplicate.yaml":     validExceptionYAML,
			}),
			wantLen: -1,
		},
		{
			name: "normalises image on load",
			directory: createDirectory(t, map[string]string{
				"kafka/CVE-2026-2332.yaml": strings.Replace(validExceptionYAML, "quay.io/stackstate/kafka", "quay.io/stackstate/kafka:v1.2.3", 1),
			}),
			expectedKey: []ExceptionKey{{Image: "quay.io/stackstate/kafka", CVE: "CVE-2026-2332"}},
			wantLen:     1,
		},
		{
			name: "bad schema version",
			directory: createDirectory(t, map[string]string{
				"kafka/CVE-2026-2332.yaml": strings.Replace(validExceptionYAML, `"1"`, `"99"`, 1),
			}),
			wantLen: -1,
		},
		{
			name: "ignores non yaml",
			directory: createDirectory(t, map[string]string{
				"kafka/CVE-2026-2332.yaml": validExceptionYAML,
				"kafka/README.md":          "# notes",
				"kafka/notes.txt":          "stray",
			}),
			wantLen: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := LoadExceptions(tt.directory)

			if tt.wantLen == -1 {
				// skip the rest of the test in case of errors
				require.Error(t, err)
				return
			} else {
				require.NoError(t, err)
			}

			require.Len(t, got, tt.wantLen)

			for _, expected := range tt.expectedKey {
				require.Contains(t, got, expected)
			}
		})
	}
}
