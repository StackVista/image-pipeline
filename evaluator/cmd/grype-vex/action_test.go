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

func TestActionGrypeCaching(t *testing.T) {
	data, err := os.ReadFile("../../../.github/actions/scan-image/action.yml")
	if err != nil {
		t.Fatal(err)
	}
	type step struct {
		Name string            `yaml:"name"`
		If   string            `yaml:"if"`
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
	for i, step := range action.Runs.Steps {
		steps[step.Name], indices[step.Name] = step, i
	}
	for _, cache := range []struct{ name, path, present, id, key string }{
		{"binary download", "grype_install_cache", "grype_install_present", "grype-binary-cache",
			"grype-binary-${{ runner.os }}-${{ runner.arch }}-${{ steps.paths.outputs.grype_version }}"},
		{"vulnerability database", "grype_cache", "grype_db_present", "grype-db-cache",
			"grype-db-${{ runner.os }}-${{ steps.paths.outputs.grype_version }}-${{ steps.paths.outputs.cache_day }}"},
	} {
		restore, save := steps["Restore Grype "+cache.name], steps["Save Grype "+cache.name]
		condition := "inputs.with-grype == 'true' && steps.paths.outputs." + cache.present + " != 'true'"
		if restore.If != "${{ "+condition+" }}" || !strings.Contains(save.If, condition) ||
			!strings.Contains(save.If, "steps."+cache.id+".outputs.cache-hit != 'true'") ||
			restore.With["path"] != "${{ steps.paths.outputs."+cache.path+" }}" ||
			save.With["path"] != restore.With["path"] || restore.With["key"] != cache.key ||
			save.With["key"] != "${{ steps."+cache.id+".outputs.cache-primary-key }}" {
			t.Fatalf("Grype %s must reuse local files and save only on a cache miss", cache.name)
		}
		setup := "Set up Grype"
		if cache.id == "grype-db-cache" {
			setup = "Grype vuln scan"
			if restore.With["restore-keys"] != "grype-db-${{ runner.os }}-${{ steps.paths.outputs.grype_version }}-\n" {
				t.Fatal("Grype databases need a compatible fallback key")
			}
		}
		if !(indices["Restore Grype "+cache.name] < indices[setup] &&
			indices[setup] < indices["Save Grype "+cache.name] &&
			indices["Save Grype "+cache.name] < indices["Evaluate"]) ||
			strings.Contains(save.If, "always()") || strings.Contains(save.If, "failure()") {
			t.Fatalf("Grype %s must save after success and before policy evaluation", cache.name)
		}
	}
	scan := steps["Grype vuln scan"]
	if scan.Env["GRYPE_DB_CACHE_DIR"] != "${{ steps.paths.outputs.grype_cache }}" ||
		scan.Env["GRYPE_CHECK_FOR_APP_UPDATE"] != "false" {
		t.Fatal("Grype must use the restored database and disable application update checks")
	}
	for _, setting := range []string{"GRYPE_DB_AUTO_UPDATE", "GRYPE_DB_VALIDATE_AGE", "GRYPE_DB_VALIDATE_BY_HASH_ON_START"} {
		if scan.Env[setting] == "false" {
			t.Fatalf("Grype database validation/update disabled: %s", setting)
		}
	}
	actionPath, err := filepath.Abs("../../../.github/actions/scan-image")
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"default", "xdg", "custom"} {
		for _, present := range []bool{false, true} {
			root := t.TempDir()
			cache, xdg, override := filepath.Join(root, ".cache/grype/db"), "", ""
			if scenario == "xdg" {
				xdg = filepath.Join(root, "xdg cache")
				cache = filepath.Join(xdg, "grype/db")
			} else if scenario == "custom" {
				override = filepath.Join(root, "custom db")
				cache = override
			}
			if present {
				writeCLIFile(t, filepath.Join(cache, "6/vulnerability.db"), []byte("db"))
				binaryCache := filepath.Join(root, ".cache/image-pipeline/grype/0.118.0/Linux-X64")
				writeCLIFile(t, filepath.Join(binaryCache, "grype.tar.gz"), []byte("archive"))
				writeCLIFile(t, filepath.Join(binaryCache, "checksums.txt"), []byte("checksums"))
			}
			output := filepath.Join(root, "outputs")
			command := exec.Command("bash", "-eu", "-c", steps["Resolve repo root"].Run)
			command.Env = append(os.Environ(), "HOME="+root, "XDG_CACHE_HOME="+xdg,
				"GRYPE_DB_CACHE_DIR="+override, "GRYPE_VERSION=0.118.0", "RUNNER_OS=Linux", "RUNNER_ARCH=X64",
				"ACTION_PATH="+actionPath, "GITHUB_OUTPUT="+output)
			if log, err := command.CombinedOutput(); err != nil {
				t.Fatalf("Grype cache resolution failed: %v\n%s", err, log)
			}
			resolved, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			expected := "false"
			if present {
				expected = "true"
			}
			for _, line := range []string{"grype_cache=" + cache,
				"grype_db_present=" + expected, "grype_install_present=" + expected} {
				if !strings.Contains(string(resolved), line+"\n") {
					t.Fatalf("missing %q in cache outputs: %s", line, resolved)
				}
			}
		}
	}
}

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
	if !strings.Contains(steps["Save Trivy Java database"].If, "steps.trivy-databases.outputs.java_db_updated == 'true'") ||
		!(indices["Restore Trivy Java database"] < indices["Read Trivy Java metadata"] &&
			indices["Read Trivy Java metadata"] < indices["Trivy vuln scan"]) {
		t.Fatal("unchanged restored Java metadata must not occupy a new cache key")
	}
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
			metadata := runOutputs(steps["Read Trivy Java metadata"].Run, filepath.Join(root, "metadata"), "TRIVY_CACHE="+cache)
			after := runOutputs(steps["Check Trivy databases"].Run, filepath.Join(root, "after"),
				"TRIVY_CACHE="+cache, "JAVA_DB_HASH="+metadata["hash"])
			if after["java_db_updated"] != "false" {
				t.Fatalf("an absent or unchanged Java database must not be saved: %v", after)
			}
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
			if err := os.WriteFile(filepath.Join(cache, "java-db/metadata.json"), []byte(`{"DownloadedAt":"2026-11-04T10:00:00Z"}`), 0644); err != nil {
				t.Fatal(err)
			}
			updated := runOutputs(steps["Check Trivy databases"].Run, filepath.Join(root, "updated"),
				"TRIVY_CACHE="+cache, "JAVA_DB_HASH="+metadata["hash"])
			if updated["java_db_present"] != "true" || updated["java_db_updated"] != "true" {
				t.Fatalf("new or updated Java metadata must be eligible for saving: %v", updated)
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
