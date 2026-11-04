package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestActionTrivyCaching(t *testing.T) {
	data, err := os.ReadFile("../../../.github/actions/scan-image/action.yml")
	if err != nil {
		t.Fatal(err)
	}
	var action struct {
		Runs struct {
			Steps []struct {
				Name string            `yaml:"name"`
				ID   string            `yaml:"id"`
				If   string            `yaml:"if"`
				Run  string            `yaml:"run"`
				With map[string]string `yaml:"with"`
			} `yaml:"steps"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal(data, &action); err != nil {
		t.Fatal(err)
	}
	var paths string
	var binaryCached, databaseCached, databaseSaved bool
	databasePaths := "${{ steps.paths.outputs.trivy_cache }}/db\n${{ steps.paths.outputs.trivy_cache }}/java-db\n"
	scan, save, evaluate := -1, -1, -1
	for i, step := range action.Runs.Steps {
		switch step.Name {
		case "Set up Trivy":
			binaryCached = step.With["cache"] == "true"
		case "Resolve repo root":
			paths = step.Run
		case "Restore Trivy databases":
			databaseCached = step.ID == "trivy-db-cache" && step.With["path"] == databasePaths &&
				strings.Contains(step.With["key"], "${{ steps.paths.outputs.cache_day }}") &&
				step.With["restore-keys"] == "trivy-db-${{ runner.os }}-\n"
		case "Save Trivy databases":
			save = i
			databaseSaved = step.With["path"] == databasePaths &&
				step.With["key"] == "${{ steps.trivy-db-cache.outputs.cache-primary-key }}" &&
				step.If == "${{ steps.trivy-db-cache.outputs.cache-hit != 'true' }}"
		case "Trivy vuln scan":
			scan = i
			if strings.Contains(step.Run, "--skip-db-update") || strings.Contains(step.Run, "--skip-java-db-update") {
				t.Fatal("database freshness checks are disabled")
			}
		case "Evaluate":
			evaluate = i
		}
	}
	if !binaryCached || !databaseCached || !databaseSaved || !(scan < save && save < evaluate) {
		t.Fatalf("Trivy caching is incomplete: binary=%v restore=%v save=%v scan/save/evaluate=%d/%d/%d",
			binaryCached, databaseCached, databaseSaved, scan, save, evaluate)
	}
	actionPath, err := filepath.Abs("../../../.github/actions/scan-image")
	if err != nil {
		t.Fatal(err)
	}
	for _, custom := range []bool{false, true} {
		root := t.TempDir()
		cache := filepath.Join(root, ".cache/trivy")
		override := ""
		if custom {
			override = filepath.Join(root, "custom cache")
			cache = override
		}
		output := filepath.Join(root, "output")
		command := exec.Command("bash", "-e", "-c", paths)
		command.Env = append(os.Environ(), "HOME="+root, "TRIVY_CACHE_DIR="+override,
			"ACTION_PATH="+actionPath, "GITHUB_OUTPUT="+output)
		if log, err := command.CombinedOutput(); err != nil {
			t.Fatalf("cache path resolution failed: %v\n%s", err, log)
		}
		resolved, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(resolved), "trivy_cache="+cache+"\n") ||
			!regexp.MustCompile(`(?m)^cache_day=\d{4}-\d{2}-\d{2}$`).Match(resolved) {
			t.Fatalf("unexpected cache outputs: %s", resolved)
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
