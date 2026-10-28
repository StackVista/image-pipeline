package main

import (
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
	for _, scenario := range []string{"success", "empty download", "download failure", "install failure", "missing binary", "wrong version"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			tools := filepath.Join(root, "tools")
			// Simulate the pinned installer, including its delegation switch.
			installer := `#!/bin/sh
set -eu
test "${DOWNLOAD_TAG_INSTALL_SCRIPT}" = false
test "$1" = -b
test "$2" = /usr/local/bin
test "$3" = v0.118.0
test "$TASK_SCENARIO" != "install failure"
if [ "$TASK_SCENARIO" != "missing binary" ]; then
  cp "$TASK_GRYPE_FIXTURE" "$TASK_TOOLS/grype"
  chmod +x "$TASK_TOOLS/grype"
fi
`
			curl := `#!/bin/bash
set -eu
test "$TASK_SCENARIO" != "download failure"
while [ "$1" != --output ]; do shift; done
if [ "$TASK_SCENARIO" = "empty download" ]; then
  : > "$2"
else
  cp "$TASK_INSTALLER" "$2"
fi
`
			version := "0.118.0"
			if scenario == "wrong version" {
				version = "0.117.0"
			}
			grype := "#!/bin/sh\nprintf '%s\\n' '{\"version\":\"" + version + "\"}'\n"
			writeCLIFile(t, filepath.Join(root, "installer"), []byte(installer))
			writeCLIFile(t, filepath.Join(root, "grype"), []byte(grype))
			writeCLIFile(t, filepath.Join(tools, "curl"), []byte(curl))
			writeCLIFile(t, filepath.Join(tools, "sudo"), []byte("#!/bin/sh\nexec \"$@\"\n"))
			for _, name := range []string{"curl", "sudo"} {
				if err := os.Chmod(filepath.Join(tools, name), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			// Prevent any Grype on the developer's PATH masking a missing install.
			script = strings.ReplaceAll(script, "grype version", `"${TASK_TOOLS}/grype" version`)
			command := exec.Command("bash", "-c", script)
			command.Dir = root
			command.Env = append(os.Environ(),
				"PATH="+tools+":"+os.Getenv("PATH"), "RUNNER_TEMP="+root,
				"GRYPE_VERSION=0.118.0", "INSTALL_SHA=test-only",
				"TASK_SCENARIO="+scenario, "TASK_TOOLS="+tools,
				"TASK_INSTALLER="+filepath.Join(root, "installer"),
				"TASK_GRYPE_FIXTURE="+filepath.Join(root, "grype"))
			log, err := command.CombinedOutput()
			if (err == nil) != (scenario == "success") {
				t.Fatalf("unexpected installation result: %v\n%s", err, log)
			}
		})
	}
}
