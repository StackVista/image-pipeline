package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/StackVista/image-pipeline/evaluator/internal/grypevex"
)

func main() {
	cache := flag.String("cache-dir", "", "Trivy VEX repository cache directory")
	config := flag.String("config", "", "Trivy VEX repository configuration")
	output := flag.String("output-dir", "", "Directory for locally converted VEX documents")
	list := flag.String("documents-list", "", "Output file listing Grype VEX document paths")
	mode := flag.String("mode", "gate", "gate or inform")
	flag.Parse()
	if *cache == "" || *config == "" || *output == "" || *list == "" ||
		(*mode != "gate" && *mode != "inform") {
		fmt.Fprintln(os.Stderr, "cache-dir, config, output-dir, documents-list and a valid mode are required")
		os.Exit(2)
	}
	prepared, problems := grypevex.Prepare(*cache, *config, *output)
	if err := os.MkdirAll(filepath.Dir(*list), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	content := strings.Join(prepared.Documents, "\n")
	if content != "" {
		content += "\n"
	}
	if err := os.WriteFile(*list, []byte(content), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, problem := range problems {
		fmt.Fprintln(os.Stderr, "VEX preparation:", problem)
	}
	for _, warning := range prepared.Warnings {
		message := strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(warning.Error())
		fmt.Fprintln(os.Stderr, "::warning::VEX preparation:", message)
	}
	fmt.Printf("Prepared %d OpenVEX document(s) and converted %d CSAF document(s) for Grype\n",
		prepared.OpenVEX, prepared.CSAF)
	if len(problems) > 0 {
		os.Exit(1)
	}
}
