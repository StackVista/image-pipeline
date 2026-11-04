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
	type step struct {
		Name string            `yaml:"name"`
		ID   string            `yaml:"id"`
		If   string            `yaml:"if"`
		Run  string            `yaml:"run"`
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
	steps := make(map[string]step)
	indices := make(map[string]int)
	for i, step := range action.Runs.Steps {
		steps[step.Name] = step
		indices[step.Name] = i
	}
	if steps["Set up Trivy"].With["cache"] != "true" {
		t.Fatal("Trivy binary caching is disabled")
	}
	scan := steps["Trivy vuln scan"]
	if strings.Contains(scan.Run, "--skip-db-update") || strings.Contains(scan.Run, "--skip-java-db-update") {
		t.Fatal("database freshness checks are disabled")
	}
	for _, database := range []struct {
		name, directory, id, prefix, period, present string
	}{
		{"vulnerability", "db", "trivy-db-cache", "trivy-vuln-db", "cache_day", "db_present"},
		{"Java", "java-db", "trivy-java-db-cache", "trivy-java-db", "java_cache_period", "java_db_present"},
	} {
		restoreName := "Restore Trivy " + database.name + " database"
		saveName := "Save Trivy " + database.name + " database"
		restore, save := steps[restoreName], steps[saveName]
		path := "${{ steps.paths.outputs.trivy_cache }}/" + database.directory
		if restore.ID != database.id || restore.With["path"] != path || save.With["path"] != path {
			t.Fatalf("%s database needs its own cache directory", database.name)
		}
		if restore.With["key"] != database.prefix+"-${{ runner.os }}-${{ steps.paths.outputs."+database.period+" }}" ||
			restore.With["restore-keys"] != database.prefix+"-${{ runner.os }}-\n" ||
			save.With["key"] != "${{ steps."+database.id+".outputs.cache-primary-key }}" {
			t.Fatalf("%s database needs its own rotating key and fallback", database.name)
		}
		localAbsent := "steps.paths.outputs." + database.present + " != 'true'"
		if restore.If != "${{ "+localAbsent+" }}" ||
			!strings.Contains(save.If, localAbsent) ||
			!strings.Contains(save.If, "steps."+database.id+".outputs.cache-hit != 'true'") ||
			!strings.Contains(save.If, "steps.trivy-databases.outputs."+database.present+" == 'true'") {
			t.Fatalf("%s cache must reuse local databases and save only present databases on a miss", database.name)
		}
		if !(indices[restoreName] < indices["Trivy vuln scan"] &&
			indices["Trivy vuln scan"] < indices["Check Trivy databases"] &&
			indices["Check Trivy databases"] < indices[saveName] && indices[saveName] < indices["Evaluate"]) {
			t.Fatalf("%s database must save after a successful scan and before policy evaluation", database.name)
		}
	}
	actionPath, err := filepath.Abs("../../../.github/actions/scan-image")
	if err != nil {
		t.Fatal(err)
	}
	runOutputs := func(script, output string, env ...string) map[string]string {
		t.Helper()
		command := exec.Command("bash", "-e", "-c", script)
		command.Env = append(os.Environ(), append(env, "GITHUB_OUTPUT="+output)...)
		if log, err := command.CombinedOutput(); err != nil {
			t.Fatalf("cache metadata resolution failed: %v\n%s", err, log)
		}
		resolved, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		values := make(map[string]string)
		for _, line := range strings.Split(strings.TrimSpace(string(resolved)), "\n") {
			key, value, _ := strings.Cut(line, "=")
			values[key] = value
		}
		return values
	}
	for _, custom := range []bool{false, true} {
		for _, existing := range [][]string{nil, {"db"}, {"java-db"}, {"db", "java-db"}} {
			root := t.TempDir()
			cache := filepath.Join(root, ".cache/trivy")
			override := ""
			if custom {
				override = filepath.Join(root, "custom cache")
				cache = override
			}
			for _, directory := range []string{"db", "java-db"} {
				path := filepath.Join(cache, directory)
				if err := os.MkdirAll(path, 0755); err != nil {
					t.Fatal(err)
				}
			}
			for _, directory := range existing {
				path := filepath.Join(cache, directory)
				if err := os.WriteFile(filepath.Join(path, "metadata.json"), []byte("{}"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			before := runOutputs(steps["Resolve repo root"].Run, filepath.Join(root, "before"),
				"HOME="+root, "TRIVY_CACHE_DIR="+override, "ACTION_PATH="+actionPath)
			after := runOutputs(steps["Check Trivy databases"].Run, filepath.Join(root, "after"), "TRIVY_CACHE="+cache)
			if before["trivy_cache"] != cache || !regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`).MatchString(before["cache_day"]) {
				t.Fatalf("unexpected cache path/date: %v", before)
			}
			for _, directory := range []string{"db", "java-db"} {
				present := "false"
				for _, cached := range existing {
					if cached == directory {
						present = "true"
					}
				}
				key := strings.ReplaceAll(directory, "-", "_") + "_present"
				if before[key] != present || after[key] != present {
					t.Fatalf("database %s presence=%s: before=%v after=%v", directory, present, before, after)
				}
			}
		}
	}
	root := t.TempDir()
	date := filepath.Join(root, "date")
	if err := os.WriteFile(date, []byte("#!/bin/sh\nif [ \"$2\" = +%s ]; then echo \"$CACHE_TEST_SECONDS\"; else echo 2026-11-04; fi\n"), 0755); err != nil {
		t.Fatal(err)
	}
	for _, rotation := range []struct{ seconds, period string }{
		{"0", "0"}, {"259199", "0"}, {"259200", "1"}, {"518399", "1"}, {"518400", "2"},
	} {
		values := runOutputs(steps["Resolve repo root"].Run, filepath.Join(root, "rotation-"+rotation.seconds),
			"HOME="+root, "TRIVY_CACHE_DIR=", "ACTION_PATH="+actionPath,
			"PATH="+root+":"+os.Getenv("PATH"), "CACHE_TEST_SECONDS="+rotation.seconds)
		if values["java_cache_period"] != rotation.period {
			t.Fatalf("Java cache must rotate every three days: seconds=%s outputs=%v", rotation.seconds, values)
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
