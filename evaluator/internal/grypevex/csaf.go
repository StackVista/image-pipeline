package grypevex

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/anchore/packageurl-go"
)

type product struct {
	ID            string    `json:"@id"`
	Subcomponents []product `json:"subcomponents,omitempty"`
}

type sourceProduct struct {
	ID     string                     `json:"product_id"`
	Helper map[string]json.RawMessage `json:"product_identification_helper"`
}

type branch struct {
	Product  sourceProduct `json:"product"`
	Branches []branch      `json:"branches"`
}

type relationship struct {
	Category        string        `json:"category"`
	Product         string        `json:"product_reference"`
	Parent          string        `json:"relates_to_product_reference"`
	FullProductName sourceProduct `json:"full_product_name"`
}

type annotation struct {
	Label      string   `json:"label"`
	Category   string   `json:"category"`
	Details    string   `json:"details"`
	ProductIDs []string `json:"product_ids"`
	GroupIDs   []string `json:"group_ids,omitempty"`
	Date       string   `json:"date,omitempty"`
}

type productGroup struct {
	ID         string   `json:"group_id"`
	ProductIDs []string `json:"product_ids"`
}

type identifier struct {
	Text string `json:"text"`
}

type advisory struct {
	Document struct {
		Category    string `json:"category"`
		CSAFVersion string `json:"csaf_version"`
		Publisher   struct {
			Name string `json:"name"`
		} `json:"publisher"`
		Tracking struct {
			Version            string `json:"version"`
			CurrentReleaseDate string `json:"current_release_date"`
		} `json:"tracking"`
	} `json:"document"`
	ProductTree struct {
		Branches         []branch        `json:"branches"`
		FullProductNames []sourceProduct `json:"full_product_names"`
		Relationships    []relationship  `json:"relationships"`
		Groups           []productGroup  `json:"product_groups,omitempty"`
	} `json:"product_tree"`
	Vulnerabilities []struct {
		CVE           string              `json:"cve"`
		IDs           []identifier        `json:"ids"`
		ProductStatus map[string][]string `json:"product_status"`
		Flags         []annotation        `json:"flags"`
		Threats       []annotation        `json:"threats"`
		Remediations  []annotation        `json:"remediations,omitempty"`
	} `json:"vulnerabilities"`
}

type statement struct {
	Vulnerability struct {
		Name string `json:"name"`
	} `json:"vulnerability"`
	Timestamp       string    `json:"timestamp"`
	Products        []product `json:"products"`
	Status          string    `json:"status"`
	Justification   string    `json:"justification,omitempty"`
	ImpactStatement string    `json:"impact_statement,omitempty"`
	ActionStatement string    `json:"action_statement,omitempty"`
	ActionTimestamp string    `json:"action_statement_timestamp,omitempty"`
}

type openVEX struct {
	Context    string      `json:"@context"`
	ID         string      `json:"@id"`
	Author     string      `json:"author"`
	Timestamp  string      `json:"timestamp"`
	Version    int         `json:"version"`
	Statements []statement `json:"statements"`
}

type productTree struct {
	products      map[string]string
	relationships map[string]relationship
	groups        map[string][]string
	normalized    map[string]string
	additionalIDs map[string]bool
}

type assessmentKey struct {
	vulnerability string
	product       string
	component     string
}

func Convert(data []byte) ([]byte, error) {
	var source advisory
	if err := json.Unmarshal(data, &source); err != nil {
		return nil, err
	}
	if source.Document.Category != "csaf_vex" || source.Document.CSAFVersion != "2.0" {
		return nil, fmt.Errorf("expected a CSAF-VEX 2.0 document")
	}
	if _, err := time.Parse(time.RFC3339, source.Document.Tracking.CurrentReleaseDate); err != nil {
		return nil, fmt.Errorf("invalid CSAF current_release_date: %w", err)
	}
	tree := productTree{
		products:      make(map[string]string),
		relationships: make(map[string]relationship),
		groups:        make(map[string][]string),
		normalized:    make(map[string]string),
		additionalIDs: make(map[string]bool),
	}
	for _, p := range source.ProductTree.FullProductNames {
		if err := tree.add(p); err != nil {
			return nil, err
		}
	}
	var visit func([]branch) error
	visit = func(branches []branch) error {
		for _, b := range branches {
			if err := tree.add(b.Product); err != nil {
				return err
			}
			if err := visit(b.Branches); err != nil {
				return err
			}
		}
		return nil
	}
	if err := visit(source.ProductTree.Branches); err != nil {
		return nil, err
	}
	for _, r := range source.ProductTree.Relationships {
		if r.FullProductName.ID == "" {
			return nil, fmt.Errorf("CSAF relationship has no full product ID")
		}
		if _, exists := tree.relationships[r.FullProductName.ID]; exists {
			return nil, fmt.Errorf("duplicate CSAF relationship product ID %q", r.FullProductName.ID)
		}
		tree.relationships[r.FullProductName.ID] = r
	}
	for _, group := range source.ProductTree.Groups {
		if group.ID == "" || len(group.ProductIDs) == 0 {
			return nil, fmt.Errorf("CSAF product group has no ID or members")
		}
		if _, exists := tree.groups[group.ID]; exists {
			return nil, fmt.Errorf("duplicate CSAF product group ID %q", group.ID)
		}
		tree.groups[group.ID] = group.ProductIDs
	}
	version, err := strconv.Atoi(source.Document.Tracking.Version)
	if err != nil || version < 1 {
		version = 1
	}
	result := openVEX{
		Context:    "https://openvex.dev/ns/v0.2.0",
		ID:         fmt.Sprintf("urn:csaf:%x", sha256.Sum256(data)),
		Author:     source.Document.Publisher.Name,
		Timestamp:  source.Document.Tracking.CurrentReleaseDate,
		Version:    version,
		Statements: []statement{},
	}
	if result.Author == "" {
		return nil, fmt.Errorf("CSAF publisher name is missing")
	}
	statuses := []struct{ csaf, openvex string }{
		{"known_not_affected", "not_affected"},
		{"fixed", "fixed"},
		{"known_affected", "affected"},
		{"under_investigation", "under_investigation"},
	}
	seen := make(map[assessmentKey]string)
	for _, vulnerability := range source.Vulnerabilities {
		for _, vulnerabilityID := range vulnerabilityIDs(vulnerability.CVE, vulnerability.IDs) {
			for _, status := range statuses {
				for _, id := range vulnerability.ProductStatus[status.csaf] {
					p, err := tree.resolve(id)
					if err != nil {
						return nil, fmt.Errorf("%s: %w", vulnerabilityID, err)
					}
					key := assessmentKey{
						vulnerability: vulnerabilityID,
						product:       tree.normalized[p.ID],
					}
					if len(p.Subcomponents) > 0 {
						key.component = tree.normalized[p.Subcomponents[0].ID]
					}
					if previous, exists := seen[key]; exists {
						if previous != status.openvex {
							return nil, fmt.Errorf("conflicting CSAF statuses for %s resolved product scope %q", vulnerabilityID, p.ID)
						}
						continue
					}
					seen[key] = status.openvex
					s := statement{
						Timestamp: result.Timestamp,
						Products:  []product{p},
						Status:    status.openvex,
					}
					s.Vulnerability.Name = vulnerabilityID
					if s.Status == "not_affected" {
						for _, flag := range vulnerability.Flags {
							applies, err := tree.applies(flag, id)
							if err != nil {
								return nil, fmt.Errorf("%s product %s: %w", vulnerabilityID, id, err)
							}
							if applies && validJustification(flag.Label) {
								s.Justification = flag.Label
								break
							}
						}
						for _, threat := range vulnerability.Threats {
							if threat.Category != "impact" {
								continue
							}
							applies, err := tree.applies(threat, id)
							if err != nil {
								return nil, fmt.Errorf("%s product %s: %w", vulnerabilityID, id, err)
							}
							if applies && strings.TrimSpace(threat.Details) != "" {
								s.ImpactStatement = threat.Details
								break
							}
						}
						if s.Justification == "" && s.ImpactStatement == "" {
							return nil, fmt.Errorf("%s product %s has no not-affected justification or impact statement", vulnerabilityID, id)
						}
					}
					if s.Status == "affected" {
						var actions []string
						var latest time.Time
						for _, remediation := range vulnerability.Remediations {
							applies, err := tree.applies(remediation, id)
							if err != nil {
								return nil, fmt.Errorf("%s product %s: %w", vulnerabilityID, id, err)
							}
							if !applies || strings.TrimSpace(remediation.Details) == "" {
								continue
							}
							if !contains(actions, remediation.Details) {
								actions = append(actions, remediation.Details)
							}
							if remediation.Date != "" {
								date, err := time.Parse(time.RFC3339, remediation.Date)
								if err != nil {
									return nil, fmt.Errorf("%s product %s has an invalid remediation date: %w", vulnerabilityID, id, err)
								}
								if date.After(latest) {
									latest = date
								}
							}
						}
						s.ActionStatement = strings.Join(actions, "\n\n")
						if s.ActionStatement == "" {
							return nil, fmt.Errorf("%s product %s has no affected action statement", vulnerabilityID, id)
						}
						if !latest.IsZero() {
							s.ActionTimestamp = latest.UTC().Format(time.RFC3339Nano)
						}
					}
					result.Statements = append(result.Statements, s)
				}
			}
		}
	}
	return json.MarshalIndent(result, "", "  ")
}

func vulnerabilityIDs(cve string, ids []identifier) []string {
	var result []string
	add := func(id string) {
		id = strings.TrimSpace(id)
		if id != "" && !contains(result, id) {
			result = append(result, id)
		}
	}
	add(cve)
	for _, id := range ids {
		if strings.HasPrefix(id.Text, "CVE-") || strings.HasPrefix(id.Text, "GHSA-") ||
			strings.HasPrefix(id.Text, "GO-") {
			add(id.Text)
		}
	}
	return result
}

func (tree *productTree) add(p sourceProduct) error {
	if p.ID == "" {
		return nil
	}
	for method := range p.Helper {
		if method != "purl" {
			tree.additionalIDs[p.ID] = true
		}
	}
	var purl string
	if raw, exists := p.Helper["purl"]; exists {
		if err := json.Unmarshal(raw, &purl); err != nil {
			return fmt.Errorf("invalid package URL for CSAF product %q: %w", p.ID, err)
		}
	}
	if purl == "" {
		return nil
	}
	parsed, err := packageurl.FromString(purl)
	if err != nil {
		return fmt.Errorf("invalid package URL for CSAF product %q: %w", p.ID, err)
	}
	canonical := parsed.String()
	if previous, exists := tree.products[p.ID]; exists && tree.normalized[previous] != canonical {
		return fmt.Errorf("conflicting PURLs for CSAF product %q", p.ID)
	}
	tree.products[p.ID] = purl
	tree.normalized[purl] = canonical
	return nil
}

func (tree *productTree) direct(id string) (product, error) {
	if _, exists := tree.relationships[id]; exists {
		return product{}, fmt.Errorf("nested CSAF relationship %q is not supported", id)
	}
	if tree.additionalIDs[id] {
		return product{}, fmt.Errorf("CSAF product %q has identification methods that cannot be preserved", id)
	}
	purl := tree.products[id]
	if !strings.HasPrefix(purl, "pkg:") {
		return product{}, fmt.Errorf("CSAF product %q has no package URL", id)
	}
	return product{ID: purl}, nil
}

func (tree *productTree) resolve(id string) (product, error) {
	r, exists := tree.relationships[id]
	if !exists {
		return tree.direct(id)
	}
	if len(r.FullProductName.Helper) > 0 {
		return product{}, fmt.Errorf("CSAF relationship %q has an identification helper that cannot be preserved", id)
	}
	switch r.Category {
	case "default_component_of", "installed_on", "installed_with":
	default:
		return product{}, fmt.Errorf("unsupported CSAF relationship category %q", r.Category)
	}
	component, err := tree.direct(r.Product)
	if err != nil {
		return product{}, err
	}
	parent, err := tree.direct(r.Parent)
	if err != nil {
		return product{}, err
	}
	parent.Subcomponents = []product{component}
	return parent, nil
}

func (tree *productTree) applies(a annotation, id string) (bool, error) {
	applies := contains(a.ProductIDs, id)
	for _, group := range a.GroupIDs {
		members, exists := tree.groups[group]
		if !exists {
			return false, fmt.Errorf("unknown CSAF product group %q", group)
		}
		applies = applies || contains(members, id)
	}
	return applies, nil
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func validJustification(value string) bool {
	switch value {
	case "component_not_present", "vulnerable_code_not_present", "vulnerable_code_not_in_execute_path",
		"vulnerable_code_cannot_be_controlled_by_adversary", "inline_mitigations_already_exist":
		return true
	}
	return false
}
