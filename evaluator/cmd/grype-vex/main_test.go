package main

import (
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIRejectsUnsafeDocumentWithoutReusingOldList(t *testing.T) {
	fixture, err := os.ReadFile("../../internal/grypevex/testdata/relationship-identity.csaf.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"gate", "inform"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			cache := filepath.Join(root, "cache")
			config := filepath.Join(root, "repository.yaml")
			list := filepath.Join(root, "documents.txt")
			good := filepath.Join(cache, "stackvista", "0.1", "document.json")
			bad := filepath.Join(cache, "rancher", "0.1", "document.json")
			writeCLIFile(t, config, []byte("repositories:\n  - name: stackvista\n    enabled: true\n  - name: rancher\n    enabled: true\n"))
			writeCLIFile(t, filepath.Join(filepath.Dir(good), "index.json"), []byte(`{"packages":[{"format":"openvex","location":"document.json"}]}`))
			writeCLIFile(t, filepath.Join(filepath.Dir(bad), "index.json"), []byte(`{"packages":[{"format":"csaf","location":"document.json"}]}`))
			writeCLIFile(t, good, []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","statements":[]}`))
			writeCLIFile(t, bad, fixture)
			writeCLIFile(t, list, []byte(bad+"\n"))
			output := filepath.Join(root, "converted")
			stale := filepath.Join(output, "stale.openvex.json")
			writeCLIFile(t, stale, []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","statements":[]}`))

			command := exec.Command(os.Args[0], "-test.run=^TestCLIHelperProcess$", "--",
				"--cache-dir", cache, "--config", config, "--output-dir", output,
				"--documents-list", list, "--mode", mode)
			command.Env = append(os.Environ(), "GRYPE_VEX_TEST_PROCESS=1")
			log, err := command.CombinedOutput()
			if mode == "gate" {
				exit, ok := err.(*exec.ExitError)
				if !ok || exit.ExitCode() != 1 {
					t.Fatalf("gate did not fail on unsafe CSAF: %v\n%s", err, log)
				}
			} else if err != nil {
				t.Fatalf("inform did not continue with valid documents: %v\n%s", err, log)
			}
			if !strings.Contains(string(log), "cannot be preserved") {
				t.Fatalf("missing unsafe-scope diagnostic: %s", log)
			}
			documents, err := os.ReadFile(list)
			if err != nil {
				t.Fatal(err)
			}
			if string(documents) != good+"\n" {
				t.Fatalf("unsafe or stale document leaked into Grype's list: %s", documents)
			}
		})
	}
}

func TestCLIHelperProcess(t *testing.T) {
	if os.Getenv("GRYPE_VEX_TEST_PROCESS") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
			flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
			main()
			os.Exit(0)
		}
	}
	t.Fatal("missing CLI arguments")
}

func writeCLIFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
