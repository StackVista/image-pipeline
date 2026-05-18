package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

// SARIF 2.1.0 emission for upload to GitHub Code Scanning. The
// image-pipeline evaluator is the producing tool: rule entries are the
// CVEs surfaced by the underlying scanner(s); results carry our
// suppression decisions (matched + unexpired exception) as SARIF
// suppressions[]. Expired exceptions are emitted as live results so
// they surface in GHAS rather than vanishing silently.
//
// Only the SARIF fields we actually emit are modelled. See
// https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
// for the GHAS-recognised subset.

const (
	sarifSchemaURL     = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifVersion       = "2.1.0"
	sarifDriverName    = "image-pipeline-evaluator"
	sarifDriverInfoURI = "https://github.com/StackVista/image-pipeline"
)

type sarifReport struct {
	Schema  string     `json:"$schema,omitempty"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool       sarifTool      `json:"tool"`
	Results    []sarifResult  `json:"results"`
	Properties *sarifRunProps `json:"properties,omitempty"`
}

type sarifRunProps struct {
	UnusedExceptions []sarifUnusedException `json:"image-pipeline.unusedExceptions,omitempty"`
}

type sarifUnusedException struct {
	CVE    string `json:"cve"`
	Image  string `json:"image"`
	Source string `json:"source"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name,omitempty"`
	ShortDescription *sarifMessage   `json:"shortDescription,omitempty"`
	HelpURI          string          `json:"helpUri,omitempty"`
	Properties       *sarifRuleProps `json:"properties,omitempty"`
}

type sarifRuleProps struct {
	Tags []string `json:"tags,omitempty"`
}

type sarifResult struct {
	RuleID              string             `json:"ruleId"`
	Level               string             `json:"level,omitempty"`
	Message             sarifMessage       `json:"message"`
	Locations           []sarifLocation    `json:"locations,omitempty"`
	PartialFingerprints map[string]string  `json:"partialFingerprints,omitempty"`
	Properties          *sarifResultProps  `json:"properties,omitempty"`
	Suppressions        []sarifSuppression `json:"suppressions,omitempty"`
}

type sarifResultProps struct {
	SecuritySeverity string   `json:"security-severity,omitempty"`
	Tags             []string `json:"tags,omitempty"`
	Scanners         []string `json:"image-pipeline.scanners,omitempty"`
	Status           string   `json:"image-pipeline.status,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation *sarifPhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifLogicalLocation struct {
	Name string `json:"name,omitempty"`
	Kind string `json:"kind,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifSuppression struct {
	Kind          string                 `json:"kind"`
	Justification string                 `json:"justification,omitempty"`
	Properties    *sarifSuppressionProps `json:"properties,omitempty"`
}

type sarifSuppressionProps struct {
	Source string `json:"image-pipeline.source,omitempty"`
}

// buildSARIF assembles a SARIF report from evaluator decisions.
// `unusedKeys` and `exceptions` are surfaced as run-level properties
// for hygiene visibility — exceptions whose CVE didn't fire in this
// scan are likely stale and worth cleaning up.
func buildSARIF(
	image string,
	decisions []Decision,
	unusedKeys []ExceptionKey,
	exceptions map[ExceptionKey]Exception,
	evaluatorVersion string,
) sarifReport {
	rulesByID := map[string]sarifRule{}
	results := make([]sarifResult, 0, len(decisions))

	for _, d := range decisions {
		f := d.Finding
		if _, ok := rulesByID[f.VulnerabilityID]; !ok {
			rulesByID[f.VulnerabilityID] = ruleFor(f)
		}

		level, secSev := levelFor(f.Severity)
		props := &sarifResultProps{
			SecuritySeverity: secSev,
			Tags:             []string{"security", "vulnerability"},
			Scanners:         f.SourceScanners,
		}

		msg := fmt.Sprintf("%s in %s@%s [%s]", f.VulnerabilityID, f.PackageName, f.PackageVersion, f.Severity)
		result := sarifResult{
			RuleID:              f.VulnerabilityID,
			Level:               level,
			Message:             sarifMessage{Text: msg},
			Locations:           locationsFor(f),
			PartialFingerprints: map[string]string{"primaryLocationLineHash": fingerprint(image, f)},
			Properties:          props,
		}

		switch {
		case d.Suppressed != nil:
			result.Suppressions = []sarifSuppression{{
				Kind:          "external",
				Justification: d.Suppressed.Justification,
				Properties:    &sarifSuppressionProps{Source: d.Suppressed.Source},
			}}
		case d.Expired != nil:
			props.Status = "expired"
			result.Message.Text = fmt.Sprintf("%s — exception %s expired %s",
				msg, d.Expired.SourcePath, d.Expired.Expires)
		}

		results = append(results, result)
	}

	rules := make([]sarifRule, 0, len(rulesByID))
	for _, r := range rulesByID {
		rules = append(rules, r)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })

	var runProps *sarifRunProps
	if len(unusedKeys) > 0 {
		unused := make([]sarifUnusedException, 0, len(unusedKeys))
		for _, k := range unusedKeys {
			unused = append(unused, sarifUnusedException{
				CVE:    k.CVE,
				Image:  k.Image,
				Source: exceptions[k].SourcePath,
			})
		}
		runProps = &sarifRunProps{UnusedExceptions: unused}
	}

	return sarifReport{
		Schema:  sarifSchemaURL,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           sarifDriverName,
					Version:        evaluatorVersion,
					InformationURI: sarifDriverInfoURI,
					Rules:          rules,
				},
			},
			Results:    results,
			Properties: runProps,
		}},
	}
}

// writeSARIF serialises the SARIF document to w as indented JSON.
func writeSARIF(w io.Writer, image string, decisions []Decision, unusedKeys []ExceptionKey, exceptions map[ExceptionKey]Exception, evaluatorVersion string) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(buildSARIF(image, decisions, unusedKeys, exceptions, evaluatorVersion))
}

func ruleFor(f Finding) sarifRule {
	r := sarifRule{
		ID:         f.VulnerabilityID,
		Name:       f.VulnerabilityID,
		Properties: &sarifRuleProps{Tags: []string{"security", "vulnerability"}},
	}
	if f.PrimaryURL != "" {
		r.HelpURI = f.PrimaryURL
		r.ShortDescription = &sarifMessage{Text: f.VulnerabilityID + " — see " + f.PrimaryURL}
	} else {
		r.ShortDescription = &sarifMessage{Text: f.VulnerabilityID}
	}
	return r
}

// levelFor maps evaluator severity to SARIF level + GHAS
// security-severity (string-encoded 0.0–10.0). HIGH/CRITICAL are
// errors so they trip GHAS severity gates; MEDIUM is a warning; LOW
// and unknown become notes.
func levelFor(severity string) (level, securitySeverity string) {
	switch severity {
	case "CRITICAL":
		return "error", "9.5"
	case "HIGH":
		return "error", "8.0"
	case "MEDIUM":
		return "warning", "5.0"
	case "LOW":
		return "note", "2.0"
	default:
		return "note", "0.0"
	}
}

// fingerprint produces a stable hash for (image, finding) so GHAS can
// dedupe the same finding across runs even when other fields shift.
func fingerprint(image string, f Finding) string {
	h := sha256.New()
	io.WriteString(h, image)
	io.WriteString(h, "|")
	io.WriteString(h, f.VulnerabilityID)
	io.WriteString(h, "|")
	io.WriteString(h, f.PackageName)
	io.WriteString(h, "|")
	io.WriteString(h, f.PackageVersion)
	return hex.EncodeToString(h.Sum(nil))
}

// locationsFor returns SARIF locations for a finding. Each Path
// becomes a physicalLocation; PackagePURL (when present) is attached
// as a logicalLocation. Falls back to package name when nothing else
// is available — SARIF requires at least one location for GHAS to
// render a result.
func locationsFor(f Finding) []sarifLocation {
	var locs []sarifLocation
	for _, p := range f.Paths {
		locs = append(locs, sarifLocation{
			PhysicalLocation: &sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: p},
			},
		})
	}
	if f.PackagePURL != "" {
		logical := sarifLogicalLocation{Name: f.PackagePURL, Kind: "package"}
		if len(locs) > 0 {
			locs[0].LogicalLocations = []sarifLogicalLocation{logical}
		} else {
			locs = append(locs, sarifLocation{LogicalLocations: []sarifLogicalLocation{logical}})
		}
	}
	if len(locs) == 0 {
		locs = append(locs, sarifLocation{
			LogicalLocations: []sarifLogicalLocation{{Name: f.PackageName, Kind: "package"}},
		})
	}
	return locs
}
