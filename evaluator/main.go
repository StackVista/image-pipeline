// image-pipeline-evaluate — apply exception policy to scanner output
// and decide pass/fail.
//
// Exit codes:
//
//	0  gate passes (no unmanaged/expired findings) or mode is inform.
//	1  gate fails (at least one unmanaged or expired-suppression finding).
//	2  usage / loader error.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

// version is overridden at link time for tagged releases via
//
//	go build -ldflags "-X main.version=<tag>"
var version = "dev"

func main() {
	os.Exit(run())
}

func run() int {
	var (
		exceptionsDir = flag.String("exceptions", "", "Optional path to exceptions directory tree to load. Omit when the image has no managed CVE exceptions.")
		trivyJSON     = flag.String("trivy-json", "", "Path to Trivy JSON scan report (one of --trivy-json / --grype-json is required)")
		grypeJSON     = flag.String("grype-json", "", "Path to Grype JSON scan report (one of --trivy-json / --grype-json is required)")
		image         = flag.String("image", "", "Image being scanned (e.g. quay.io/stackstate/kafka). Tag/digest will be stripped.")
		severity      = flag.String("severity", "HIGH,CRITICAL", "Comma-separated severities to gate on")
		mode          = flag.String("mode", ModeGate, "Evaluation mode: gate (fail on unmanaged/expired) or inform (always exit 0)")
		sarifPath     = flag.String("sarif", "", "Optional path to write SARIF 2.1.0 output (e.g. for GHAS Code Scanning upload)")
	)
	flag.Parse()

	if *image == "" || (*trivyJSON == "" && *grypeJSON == "") {
		fmt.Fprintln(os.Stderr, "usage: image-pipeline-evaluate --image <image-ref> (--trivy-json <file> | --grype-json <file>) [--exceptions <dir>] [--severity HIGH,CRITICAL] [--mode gate|inform] [--sarif <path>]")
		return 2
	}
	if *mode != ModeGate && *mode != ModeInform {
		fmt.Fprintf(os.Stderr, "invalid --mode %q; expected %q or %q\n", *mode, ModeGate, ModeInform)
		return 2
	}

	exceptions, err := LoadExceptions(*exceptionsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load exceptions: %v\n", err)
		return 2
	}

	var findings []Finding
	if *trivyJSON != "" {
		parsed, err := parseScanFile(*trivyJSON, TrivyScanner{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "trivy: %v\n", err)
			return 2
		}
		findings = append(findings, parsed...)
	}
	if *grypeJSON != "" {
		parsed, err := parseScanFile(*grypeJSON, GrypeScanner{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "grype: %v\n", err)
			return 2
		}
		findings = append(findings, parsed...)
	}

	findings = DedupeFindings(findings)
	sev := makeSeveritySet(strings.Split(*severity, ","))
	normImage := NormaliseImage(*image)
	decisions := Evaluate(normImage, findings, exceptions, sev)
	summary := Summarise(normImage, decisions, exceptions)
	fmt.Print(summary.Format(*mode))

	if *sarifPath != "" {
		out, err := os.Create(*sarifPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "open sarif output: %v\n", err)
			return 2
		}
		if err := writeSARIF(out, normImage, decisions, summary.UnusedKeys, exceptions, version); err != nil {
			out.Close()
			fmt.Fprintf(os.Stderr, "write sarif: %v\n", err)
			return 2
		}
		if err := out.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "close sarif output: %v\n", err)
			return 2
		}
	}

	return ExitCode(*mode, summary)
}

func makeSeveritySet(keys []string) map[string]bool {
	m := make(map[string]bool, len(keys))
	for _, k := range keys {
		m[strings.ToUpper(strings.TrimSpace(k))] = true
	}
	return m
}

func parseScanFile(path string, s Scanner) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	findings, err := s.Parse(f)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return findings, nil
}
