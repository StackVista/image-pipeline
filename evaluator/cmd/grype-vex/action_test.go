package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestActionScannerCaching(t *testing.T) {
	data, err := os.ReadFile("../../../.github/actions/scan-image/action.yml")
	if err != nil {
		t.Fatal(err)
	}
	type step struct {
		Name string            `yaml:"name"`
		ID   string            `yaml:"id"`
		If   string            `yaml:"if"`
		Uses string            `yaml:"uses"`
		Run  string            `yaml:"run"`
		Env  map[string]string `yaml:"env"`
		With map[string]string `yaml:"with"`
	}
	var action struct {
		Runs struct {
			Steps []step `yaml:"steps"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal(data, &action); err != nil {
		t.Fatal(err)
	}
	steps, indices := make(map[string]step), make(map[string]int)
	cacheSteps := 0
	for i, step := range action.Runs.Steps {
		steps[step.Name], indices[step.Name] = step, i
		if strings.HasPrefix(step.Uses, "actions/cache/") {
			cacheSteps++
		}
	}
	if cacheSteps != 4 {
		t.Fatal("only the two scanner binaries may be restored and saved")
	}
	for _, scanner := range []struct{ name, label, file, gate, verify string }{
		{"trivy", "Trivy binary", "/trivy", "", "Verify Trivy binary"},
		{"grype", "Grype binary download", "/grype.tar.gz", "inputs.with-grype == 'true' && ", "Set up Grype"},
	} {
		restore, save := steps["Restore "+scanner.label], steps["Save "+scanner.label]
		localAbsent := scanner.gate + "steps.paths.outputs." + scanner.name + "_install_present != 'true'"
		if restore.If != "${{ "+localAbsent+" }}" ||
			save.If != "${{ !startsWith(github.event_name, 'pull_request') && github.ref == format('refs/heads/{0}', github.event.repository.default_branch) && "+localAbsent+" && steps."+scanner.name+"-binary-cache.outputs.cache-hit != 'true' }}" ||
			restore.With["path"] != "${{ steps.paths.outputs."+scanner.name+"_install_cache }}"+scanner.file ||
			save.With["path"] != restore.With["path"] ||
			restore.With["key"] != scanner.name+"-binary-${{ runner.os }}-${{ runner.arch }}-${{ steps.paths.outputs."+scanner.name+"_version }}" ||
			restore.With["restore-keys"] != "" ||
			save.With["key"] != "${{ steps."+scanner.name+"-binary-cache.outputs.cache-primary-key }}" {
			t.Fatalf("%s must use a version/platform key and save only verified binaries on a miss", scanner.name)
		}
		if !(indices["Restore "+scanner.label] < indices[scanner.verify] &&
			indices[scanner.verify] < indices["Save "+scanner.label] &&
			indices["Save "+scanner.label] < indices["Trivy secrets scan"]) {
			t.Fatalf("%s must be verified before saving or scanning", scanner.name)
		}
	}
	setup := steps["Set up Trivy"]
	if setup.With["cache"] != "false" ||
		setup.If != "${{ steps.paths.outputs.trivy_install_present != 'true' && steps.trivy-binary-cache.outputs.cache-hit != 'true' }}" ||
		setup.With["version"] != "v${{ steps.paths.outputs.trivy_version }}" ||
		steps["Verify Trivy binary"].Env["TRIVY_INSTALL_CACHE"] != "${{ steps.paths.outputs.trivy_install_cache }}" {
		t.Fatal("Trivy must restore outside PATH, install only on misses, and always verify")
	}
	if strings.Contains(steps["Trivy vuln scan"].Run, "--skip-db-update") ||
		strings.Contains(steps["Trivy vuln scan"].Run, "--skip-java-db-update") ||
		steps["Grype vuln scan"].Env["GRYPE_DB_CACHE_DIR"] != "" {
		t.Fatal("scanner database behavior must remain unchanged")
	}
	for _, setting := range []string{"GRYPE_DB_AUTO_UPDATE", "GRYPE_DB_VALIDATE_AGE", "GRYPE_DB_VALIDATE_BY_HASH_ON_START"} {
		if steps["Grype vuln scan"].Env[setting] == "false" {
			t.Fatalf("Grype database validation disabled: %s", setting)
		}
	}
	actionPath, err := filepath.Abs("../../../.github/actions/scan-image")
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"X64", "ARM64"} {
		for _, present := range []bool{false, true} {
			root := t.TempDir()
			trivyCache := filepath.Join(root, ".cache/image-pipeline/trivy/0.76.0/Linux-"+arch)
			grypeCache := filepath.Join(root, ".cache/image-pipeline/grype/0.118.0/Linux-"+arch)
			if present {
				writeCLIFile(t, filepath.Join(trivyCache, "trivy"), []byte("binary"))
				writeCLIFile(t, filepath.Join(grypeCache, "grype.tar.gz"), []byte("archive"))
			}
			output := filepath.Join(root, "outputs")
			command := exec.Command("bash", "-eu", "-c", steps["Resolve repo root"].Run)
			command.Env = append(os.Environ(), "HOME="+root, "TRIVY_VERSION=0.76.0", "GRYPE_VERSION=0.118.0",
				"RUNNER_OS=Linux", "RUNNER_ARCH="+arch, "ACTION_PATH="+actionPath, "GITHUB_OUTPUT="+output)
			if log, err := command.CombinedOutput(); err != nil {
				t.Fatalf("cache resolution: %v\n%s", err, log)
			}
			resolved, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			expected := "false"
			if present {
				expected = "true"
			}
			for _, line := range []string{"trivy_install_cache=" + trivyCache, "grype_install_cache=" + grypeCache,
				"trivy_install_present=" + expected, "grype_install_present=" + expected} {
				if !strings.Contains(string(resolved), line+"\n") {
					t.Fatalf("missing %q: %s", line, resolved)
				}
			}
		}
	}
}

func TestActionVEXPreparation(t *testing.T) {
	data, err := os.ReadFile("../../../.github/actions/scan-image/action.yml")
	if err != nil {
		t.Fatal(err)
	}
	var action struct {
		Runs struct {
			Steps []struct {
				Name string `yaml:"name"`
				Run  string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal(data, &action); err != nil {
		t.Fatal(err)
	}
	var script string
	for _, step := range action.Runs.Steps {
		if step.Name == "Configure and download VEX repos" {
			script = strings.ReplaceAll(step.Run, "~/.trivy/vex", `"${TASK_VEX_CONFIG}"`)
		}
	}
	if script == "" {
		t.Fatal("VEX preparation step not found")
	}
	config, err := os.ReadFile("../../../vex/repository.yaml")
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile("../../internal/grypevex/testdata/zookeeper.csaf.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"gate", "inform"} {
		for _, scenario := range []string{"unsupported document", "missing index", "all rejected", "internal rejection", "download failure", "download failure without Grype"} {
			t.Run(mode+"/"+scenario, func(t *testing.T) {
				root := t.TempDir()
				tools := filepath.Join(root, "tools")
				writeCLIFile(t, filepath.Join(root, "vex/repository.yaml"), config)
				rancher := filepath.Join(root, "cache/vex/repositories/rancher/0.1")
				internal := filepath.Join(root, "cache/vex/repositories/stackvista/0.1")
				writeCLIFile(t, filepath.Join(rancher, "index.json"), []byte(`{"packages":[{"format":"csaf","location":"good.json"},{"format":"csaf","location":"bad.json"}]}`))
				writeCLIFile(t, filepath.Join(rancher, "good.json"), fixture)
				writeCLIFile(t, filepath.Join(rancher, "bad.json"), []byte("{}"))
				writeCLIFile(t, filepath.Join(internal, "index.json"), []byte(`{"packages":[{"format":"openvex","location":"good.json"}]}`))
				writeCLIFile(t, filepath.Join(internal, "good.json"), []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","statements":[]}`))
				switch scenario {
				case "missing index":
					if err := os.Remove(filepath.Join(rancher, "index.json")); err != nil {
						t.Fatal(err)
					}
				case "all rejected":
					writeCLIFile(t, filepath.Join(rancher, "good.json"), []byte("{}"))
				case "internal rejection":
					writeCLIFile(t, filepath.Join(internal, "good.json"), []byte("{}"))
				}
				downloadExit := "0"
				if strings.HasPrefix(scenario, "download failure") {
					downloadExit = "1"
				}
				writeCLIFile(t, filepath.Join(tools, "trivy"), []byte("#!/bin/bash\nexit "+downloadExit+"\n"))
				writeCLIFile(t, filepath.Join(tools, "image-pipeline-grype-vex"),
					[]byte("#!/bin/bash\nexec \"$TASK_TEST_BINARY\" -test.run=^TestCLIHelperProcess$ -- \"$@\"\n"))
				for _, name := range []string{"trivy", "image-pipeline-grype-vex"} {
					if err := os.Chmod(filepath.Join(tools, name), 0o755); err != nil {
						t.Fatal(err)
					}
				}
				withGrype := "true"
				if scenario == "download failure without Grype" {
					withGrype = "false"
				}
				command := exec.Command("bash", "-c", script)
				command.Dir = root
				command.Env = append(os.Environ(),
					"PATH="+tools+":"+os.Getenv("PATH"),
					"REPO_ROOT="+root, "INPUT_MODE="+mode, "INPUT_WITH_GRYPE="+withGrype,
					"TRIVY_CACHE_DIR="+filepath.Join(root, "cache"),
					"TASK_VEX_CONFIG="+filepath.Join(root, "config"),
					"TASK_TEST_BINARY="+os.Args[0], "GRYPE_VEX_TEST_PROCESS=1")
				log, err := command.CombinedOutput()
				if scenario != "unsupported document" {
					exit, ok := err.(*exec.ExitError)
					if !ok || exit.ExitCode() != 1 {
						t.Fatalf("feed error did not fail action: %v\n%s", err, log)
					}
					return
				}
				if err != nil || !strings.Contains(string(log), "::warning::") ||
					!strings.Contains(string(log), "bad.json") {
					t.Fatalf("document skip did not warn and succeed: %v\n%s", err, log)
				}
				list, err := os.ReadFile(filepath.Join(root, "reports/grype-vex-documents.txt"))
				if err != nil || len(strings.Split(strings.TrimSpace(string(list)), "\n")) != 2 ||
					strings.Contains(string(list), "bad.json") {
					t.Fatalf("unexpected Grype inputs: %s %v", list, err)
				}
			})
		}
	}
}
