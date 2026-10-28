package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestGrypeInstallation(t *testing.T) {
	data, err := os.ReadFile("../../../.github/actions/scan-image/action.yml")
	if err != nil {
		t.Fatal(err)
	}
	var action struct {
		Runs struct {
			Steps []struct {
				Name string
				Run  string
			}
		}
	}
	if err := yaml.Unmarshal(data, &action); err != nil {
		t.Fatal(err)
	}
	var script string
	for _, step := range action.Runs.Steps {
		if step.Name == "Set up Grype" {
			script = step.Run
		}
	}
	if script == "" {
		t.Fatal("Grype installation step not found")
	}
	for _, scenario := range []string{
		"success", "arm64", "empty archive", "empty checksums", "download failure",
		"checksum mismatch", "missing checksum", "duplicate checksum", "malformed checksum",
		"install failure", "missing binary", "wrong version",
	} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			tools := filepath.Join(root, "tools")
			arch := "amd64"
			machine := "x86_64"
			if scenario == "arm64" {
				arch, machine = "arm64", "aarch64"
			}
			curl := `#!/bin/bash
set -eu
test "$TASK_SCENARIO" != "download failure"
url="${@: -3:1}"
case "$url" in
  "https://github.com/anchore/grype/releases/download/v0.118.0/grype_0.118.0_linux_${TASK_ARCH}.tar.gz")
    fixture="$TASK_ARCHIVE"
    empty="empty archive"
    ;;
  "https://github.com/anchore/grype/releases/download/v0.118.0/grype_0.118.0_checksums.txt")
    fixture="$TASK_CHECKSUMS"
    empty="empty checksums"
    ;;
  *) exit 99 ;;
esac
while [ "$1" != --output ]; do shift; done
if [ "$TASK_SCENARIO" = "$empty" ]; then
  : > "$2"
else
  cp "$fixture" "$2"
fi
`
			// Only redirect the privileged destination; use the real install
			// command, tar extraction, and sha256sum verification.
			sudo := `#!/bin/sh
set -eu
touch "$TASK_INSTALL_CALLED"
test "$1" = install
test "$2" = -m
test "$3" = 0755
test "$5" = /usr/local/bin/grype
test "$TASK_SCENARIO" != "install failure"
if [ "$TASK_SCENARIO" != "missing binary" ]; then
  install -m 0755 "$4" "$TASK_TOOLS/grype"
fi
`
			version := "0.118.0"
			if scenario == "wrong version" {
				version = "0.117.0"
			}
			grype := "#!/bin/sh\ntouch \"$TASK_BINARY_EXECUTED\"\nprintf '%s\\n' '{\"version\":\"" + version + "\"}'\n"
			writeCLIFile(t, filepath.Join(root, "grype"), []byte(grype))
			archive := filepath.Join(root, "fixture.tar.gz")
			if log, err := exec.Command("tar", "-czf", archive, "-C", root, "grype").CombinedOutput(); err != nil {
				t.Fatalf("create release fixture: %v\n%s", err, log)
			}
			archiveData, err := os.ReadFile(archive)
			if err != nil {
				t.Fatal(err)
			}
			checksum := fmt.Sprintf("%x  grype_0.118.0_linux_%s.tar.gz\n", sha256.Sum256(archiveData), arch)
			switch scenario {
			case "checksum mismatch":
				checksum = strings.Repeat("0", 64) + "  grype_0.118.0_linux_" + arch + ".tar.gz\n"
			case "missing checksum":
				checksum = strings.ReplaceAll(checksum, "_linux_", "_darwin_")
			case "duplicate checksum":
				checksum += checksum
			case "malformed checksum":
				checksum = "invalid  grype_0.118.0_linux_" + arch + ".tar.gz\n"
			}
			writeCLIFile(t, filepath.Join(root, "checksums"), []byte(checksum))
			writeCLIFile(t, filepath.Join(tools, "curl"), []byte(curl))
			writeCLIFile(t, filepath.Join(tools, "sudo"), []byte(sudo))
			writeCLIFile(t, filepath.Join(tools, "uname"),
				[]byte("#!/bin/sh\ncase \"$1\" in -s) echo Linux;; -m) echo "+machine+";; *) exit 99;; esac\n"))
			for _, name := range []string{"curl", "sudo", "uname"} {
				if err := os.Chmod(filepath.Join(tools, name), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			// Prevent any Grype on the developer's PATH masking a missing install.
			testScript := strings.ReplaceAll(script, "grype version", `"${TASK_TOOLS}/grype" version`)
			command := exec.Command("bash", "-c", testScript)
			command.Dir = root
			command.Env = append(os.Environ(),
				"PATH="+tools+":"+os.Getenv("PATH"), "RUNNER_TEMP="+root,
				"GRYPE_VERSION=0.118.0", "TASK_ARCH="+arch,
				"TASK_SCENARIO="+scenario, "TASK_TOOLS="+tools,
				"TASK_ARCHIVE="+archive, "TASK_CHECKSUMS="+filepath.Join(root, "checksums"),
				"TASK_INSTALL_CALLED="+filepath.Join(root, "install-called"),
				"TASK_BINARY_EXECUTED="+filepath.Join(root, "binary-executed"))
			log, err := command.CombinedOutput()
			if (err == nil) != (scenario == "success" || scenario == "arm64") {
				t.Fatalf("unexpected installation result: %v\n%s", err, log)
			}
			if strings.Contains(scenario, "checksum") || strings.HasPrefix(scenario, "empty") ||
				scenario == "download failure" {
				for _, marker := range []string{"install-called", "binary-executed", "tools/grype"} {
					if _, err := os.Stat(filepath.Join(root, marker)); !os.IsNotExist(err) {
						t.Fatalf("invalid download reached installation/execution (%s): %v\n%s", marker, err, log)
					}
				}
			}
			if scenario == "checksum mismatch" && !strings.Contains(string(log), "FAILED") {
				t.Fatalf("checksum mismatch did not reach real verification:\n%s", log)
			}
		})
	}
}
