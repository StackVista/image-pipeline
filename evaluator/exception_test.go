package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestLoadExceptionsYAMLValues(t *testing.T) {
	dir := createDirectory(t, map[string]string{
		"exception.yaml": `schema_version: 1
vulnerability:
  id: &cve CVE-2026-2332
  severity: HIGH
product:
  image: quay.io/stackstate/kafka:v1.2.3
component:
  name: *cve
  paths: null
status: accepted_pending_upstream_fix
reason: on
expires: 2099-01-01
owner: 123
statement: |
  first line
  second line
review: null
unknown_field: true
`,
	})

	exceptions, err := LoadExceptions(dir)
	require.NoError(t, err)
	require.Len(t, exceptions, 1)
	ex := exceptions[ExceptionKey{Image: testImage, CVE: "CVE-2026-2332"}]
	require.Equal(t, "1", ex.SchemaVersion)
	require.Equal(t, "CVE-2026-2332", ex.Component.Name)
	require.Nil(t, ex.Component.Paths)
	require.Nil(t, ex.Review)
	require.Equal(t, "on", ex.Reason)
	require.Equal(t, "123", ex.Owner)
	require.Equal(t, "2099-01-01", ex.Expires)
	require.Equal(t, "first line\nsecond line\n", ex.Statement)
	require.Equal(t, filepath.Join(dir, "exception.yaml"), ex.SourcePath)
}

func TestLoadExceptionsRejectsMalformedYAML(t *testing.T) {
	for name, body := range map[string]string{
		"invalid syntax": validExceptionYAML + "review: [\n",
		"duplicate key":  validExceptionYAML + "expires: 2099-02-01\n",
		"unknown alias":  validExceptionYAML + "review: *missing\n",
		"wrong field type": strings.Replace(validExceptionYAML,
			"expires: 2099-01-01", "expires: [2099-01-01]", 1),
	} {
		t.Run(name, func(t *testing.T) {
			dir := createDirectory(t, map[string]string{"exception.yaml": body})
			_, err := LoadExceptions(dir)
			require.ErrorContains(t, err, filepath.Join(dir, "exception.yaml"))
		})
	}
}

func TestLoadedExceptionsPreservePolicy(t *testing.T) {
	today := time.Now().UTC()
	for _, tt := range []struct {
		name    string
		expires string
		expired bool
	}{
		{name: "future", expires: "2099-01-01"},
		{name: "expiry day inclusive", expires: today.Format("2006-01-02")},
		{name: "past", expires: today.AddDate(0, 0, -1).Format("2006-01-02"), expired: true},
		{name: "invalid date", expires: "not-a-date", expired: true},
		{name: "null date", expires: "null", expired: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			body := strings.Replace(validExceptionYAML, "2099-01-01", tt.expires, 1)
			dir := createDirectory(t, map[string]string{"exception.yaml": body})
			exceptions, err := LoadExceptions(dir)
			require.NoError(t, err)
			findings := []Finding{
				{VulnerabilityID: "CVE-2026-2332", Severity: "CRITICAL"},
				{VulnerabilityID: "CVE-unmanaged", Severity: "LOW"},
			}
			decisions := Evaluate(testImage, findings, exceptions, sevSet("HIGH", "CRITICAL"))
			require.Len(t, decisions, 1)
			if tt.expired {
				require.NotNil(t, decisions[0].Expired)
				require.Nil(t, decisions[0].Suppressed)
			} else {
				require.NotNil(t, decisions[0].Suppressed)
				require.Nil(t, decisions[0].Expired)
			}
			summary := Summarise(testImage, decisions, exceptions)
			wantGate := 0
			if tt.expired {
				wantGate = 1
			}
			require.Equal(t, wantGate, ExitCode(ModeGate, summary))
			require.Equal(t, 0, ExitCode(ModeInform, summary))
		})
	}
}
