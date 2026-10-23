package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

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
