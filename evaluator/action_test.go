package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

func TestScanActionPolicy(t *testing.T) {
	repo, err := filepath.Abs("..")
	require.NoError(t, err)
	actionPath := filepath.Join(repo, ".github/actions/scan-image/action.yml")
	profile := "canonical"
	if override := os.Getenv("IMAGE_PIPELINE_TEST_ACTION"); override != "" {
		actionPath = override
		profile = os.Getenv("IMAGE_PIPELINE_TEST_VEX_PROFILE")
		require.Contains(t, []string{"canonical", "strict", "trivy-only"}, profile)
	}
	data, err := os.ReadFile(actionPath)
	require.NoError(t, err)
	var action struct {
		Runs struct {
			Steps []struct {
				Name string            `yaml:"name"`
				Run  string            `yaml:"run"`
				Env  map[string]string `yaml:"env"`
			} `yaml:"steps"`
		} `yaml:"runs"`
	}
	require.NoError(t, yaml.Unmarshal(data, &action))

	bin := t.TempDir()
	evaluator := filepath.Join(bin, "image-pipeline-evaluate")
	build := exec.Command("go", "build", "-o", evaluator, ".")
	build.Env = append(os.Environ(), "GOTOOLCHAIN=auto")
	output, err := build.CombinedOutput()
	require.NoError(t, err, "%s", output)
	stub, err := os.ReadFile("testdata/scan-tools.py")
	require.NoError(t, err)
	stubPath := filepath.Join(bin, "scan-tools.py")
	require.NoError(t, os.WriteFile(stubPath, stub, 0o755))
	for _, tool := range []string{"trivy", "grype", "sleep", "curl", "sudo"} {
		require.NoError(t, os.Symlink(stubPath, filepath.Join(bin, tool)))
	}

	tests := []struct {
		name          string
		vex           string
		error         string
		clean         bool
		secret        bool
		malformed     bool
		exceptions    string
		vexSuppress   bool
		blockBoth     bool
		evaluatorCode string
	}{
		{name: "clean", clean: true},
		{name: "unmanaged vulnerabilities"},
		{name: "valid exceptions", exceptions: "valid"},
		{name: "expired exceptions", exceptions: "expired"},
		{name: "malformed exceptions", exceptions: "malformed", blockBoth: true, evaluatorCode: "2"},
		{name: "missing exception directory", exceptions: "missing", blockBoth: true},
		{name: "malformed scanner report", malformed: true, blockBoth: true, evaluatorCode: "2"},
		{name: "secret finding", secret: true, blockBoth: true},
		{name: "secret scanner error", error: "secret", blockBoth: true},
		{name: "vulnerability scanner error", error: "vuln", blockBoth: true},
		{name: "report conversion error", error: "convert", blockBoth: true},
		{name: "Grype error", error: "grype", blockBoth: true},
		{name: "installer error", error: "installer", blockBoth: true},
		{name: "VEX download unavailable", vex: "missing", clean: true},
		{name: "empty VEX cache", vex: "empty", clean: true},
		{name: "invalid VEX document", vex: "invalid", clean: true},
		{name: "partially available VEX", vex: "partial", clean: true},
		{name: "unavailable VEX and unmanaged vulnerabilities", vex: "missing"},
		{name: "unavailable VEX and secret", vex: "missing", secret: true, blockBoth: true},
		{name: "unavailable VEX and Grype error", vex: "missing", error: "grype", blockBoth: true},
		{name: "unavailable VEX and evaluator error", vex: "missing", malformed: true, blockBoth: true},
		{name: "VEX suppressed vulnerabilities", vexSuppress: true},
		{name: "partial VEX suppressed vulnerabilities", vex: "partial", vexSuppress: true},
	}
	for _, mode := range []string{ModeGate, ModeInform, "unknown"} {
		for _, tt := range tests {
			t.Run(mode+"/"+tt.name, func(t *testing.T) {
				dir := t.TempDir()
				home := filepath.Join(dir, "home")
				require.NoError(t, os.MkdirAll(home, 0o755))
				outPath := filepath.Join(dir, "outputs")
				require.NoError(t, os.WriteFile(outPath, nil, 0o644))
				callLog := filepath.Join(dir, "calls")
				vex := tt.vex
				if vex == "" {
					vex = "available"
				}
				exceptions := ""
				if tt.exceptions != "" {
					exceptions = filepath.Join(dir, "exceptions")
					if tt.exceptions != "missing" {
						require.NoError(t, os.Mkdir(exceptions, 0o755))
						for _, cve := range []string{"CVE-2026-2332", "CVE-2025-48734", "CVE-2099-99999"} {
							body := renderException(testImage, cve)
							if tt.exceptions == "expired" {
								body = strings.Replace(body, "2099-01-01", "2000-01-01", 1)
							} else if tt.exceptions == "malformed" {
								body = "schema_version: ["
							}
							require.NoError(t, os.WriteFile(filepath.Join(exceptions, cve+".yaml"), []byte(body), 0o644))
						}
					}
				}
				env := append(os.Environ(),
					"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
					"HOME="+home,
					"TRIVY_CACHE_DIR="+filepath.Join(home, ".cache/trivy"),
					"REPO_ROOT="+repo,
					"INPUT_IMAGE="+testImage,
					"INPUT_MODE="+mode,
					"INPUT_SEVERITY=HIGH,CRITICAL",
					"INPUT_SKIP_FILES=/fixture/excluded",
					"INPUT_EXCEPTIONS_PATH="+exceptions,
					"SARIF_PATH=reports/image-pipeline.sarif",
					"GITHUB_OUTPUT="+outPath,
					"TEST_CALL_LOG="+callLog,
					"TEST_VEX="+vex,
					"TEST_ERROR="+tt.error,
					"TEST_TRIVY_REPORT="+filepath.Join(repo, "evaluator/testdata/trivy-kafka-fixture.json"),
					"TEST_GRYPE_REPORT="+filepath.Join(repo, "evaluator/testdata/grype-kafka-fixture.json"),
				)
				for key, enabled := range map[string]bool{
					"TEST_CLEAN": tt.clean, "TEST_SECRET": tt.secret,
					"TEST_MALFORMED": tt.malformed, "TEST_VEX_SUPPRESS": tt.vexSuppress,
				} {
					value := ""
					if enabled {
						value = "1"
					}
					env = append(env, key+"="+value)
				}
				code := 0
				var logs strings.Builder
				for _, step := range action.Runs.Steps {
					if step.Name != "Set up Grype" && !strings.HasPrefix(step.Name, "Configure ") &&
						step.Name != "Trivy secrets scan" && step.Name != "Trivy vuln scan" &&
						step.Name != "Grype vuln scan" && step.Name != "Evaluate" && step.Name != "Gate result" {
						continue
					}
					if step.Name == "Gate result" {
						values, err := os.ReadFile(outPath)
						require.NoError(t, err)
						for _, line := range strings.Split(string(values), "\n") {
							if strings.HasPrefix(line, "exit-code=") {
								env = append(env, "EXIT_CODE="+strings.TrimPrefix(line, "exit-code="))
							}
						}
					}
					cmd := exec.Command("bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", step.Run)
					cmd.Dir, cmd.Env = dir, append([]string{}, env...)
					for key, value := range step.Env {
						if !strings.Contains(value, "${{") {
							cmd.Env = append(cmd.Env, key+"="+value)
						}
					}
					output, err := cmd.CombinedOutput()
					fmt.Fprintf(&logs, "%s:\n%s", step.Name, output)
					if err != nil {
						var exit *exec.ExitError
						require.ErrorAs(t, err, &exit, "%s", logs.String())
						code = exit.ExitCode()
						break
					}
				}
				wantBlocked := (mode != ModeGate && mode != ModeInform) || tt.blockBoth ||
					(mode == ModeGate && !tt.clean && tt.exceptions != "valid" && !tt.vexSuppress)
				if profile == "trivy-only" && tt.vexSuppress && mode == ModeGate {
					wantBlocked = true
				}
				if vex != "available" && profile != "trivy-only" {
					wantBlocked = wantBlocked || mode == ModeGate || profile == "strict"
				}
				require.Equal(t, wantBlocked, code != 0, "exit=%d\n%s", code, logs.String())
				values, err := os.ReadFile(outPath)
				require.NoError(t, err)
				if tt.evaluatorCode != "" {
					require.Contains(t, string(values), "exit-code="+tt.evaluatorCode, "%s", logs.String())
				}
				if profile == "canonical" && mode == ModeInform && vex != "available" && !tt.blockBoth {
					require.Contains(t, logs.String(), "::warning::")
				}
				calls, err := os.ReadFile(callLog)
				require.NoError(t, err)
				for _, line := range strings.Split(strings.TrimSpace(string(calls)), "\n") {
					var args []string
					require.NoError(t, json.Unmarshal([]byte(line), &args))
					if len(args) > 3 && args[0] == "trivy" && args[1] == "image" && args[3] == "secret" {
						require.NotContains(t, args, "--severity")
						require.NotContains(t, args, "--skip-files")
					}
				}
				if vex == "partial" && mode == ModeInform && profile == "canonical" {
					require.Contains(t, string(calls), `"--vex"`)
				}
			})
		}
	}
}
