package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Exception mirrors schemas/exception.schema.json.
type Exception struct {
	SchemaVersion     string     `yaml:"schema_version"`
	Vulnerability     VulnRef    `yaml:"vulnerability"`
	Product           ProductRef `yaml:"product"`
	Component         Component  `yaml:"component"`
	Status            string     `yaml:"status"`
	Reason            string     `yaml:"reason"`
	Expires           string     `yaml:"expires"`
	Owner             string     `yaml:"owner"`
	Statement         string     `yaml:"statement"`
	UpstreamOwner     string     `yaml:"upstream_owner,omitempty"`
	UpstreamReference string     `yaml:"upstream_reference,omitempty"`
	Review            *Review    `yaml:"review,omitempty"`

	SourcePath string `yaml:"-"` // set by loader for diagnostics
}

type VulnRef struct {
	ID       string `yaml:"id"`
	Severity string `yaml:"severity"`
}

type ProductRef struct {
	Consumer     string `yaml:"consumer"`
	Image        string `yaml:"image"`
	SourceImage  string `yaml:"source_image,omitempty"`
	SourceDigest string `yaml:"source_digest,omitempty"`
}

type Component struct {
	Name  string   `yaml:"name,omitempty"`
	PURL  string   `yaml:"purl,omitempty"`
	Paths []string `yaml:"paths,omitempty"`
}

type Review struct {
	ApprovedBy []string `yaml:"approved_by"`
	ApprovedAt string   `yaml:"approved_at"`
}

// ExceptionKey scopes an Exception by (image, CVE). The same CVE can
// have separate exceptions for different images (same upstream JAR in
// kafka vs zookeeper, different reachability stories).
type ExceptionKey struct {
	Image string
	CVE   string
}

// LoadExceptions walks `root` for *.yaml files, parses each as an
// Exception, and returns them indexed by (image, CVE). Image is
// normalised on load so tag/digest noise in the YAML doesn't break
// matching. Errors on duplicate (image, CVE) entries or unsupported
// schema_version. Non-YAML files and directories are skipped.
//
// An empty root is a valid "no exceptions configured" signal — returns
// an empty map without touching the filesystem. A non-existent path is
// still an error (typo'd subdir should fail loudly, not silently scan
// with no exceptions).
func LoadExceptions(root string) (map[ExceptionKey]Exception, error) {
	out := map[ExceptionKey]Exception{}

	// if the path is empty, no exceptions are provided
	if root == "" {
		// empty exceptions map
		return out, nil
	}

	if _, err := os.Stat(root); err != nil {
		return nil, fmt.Errorf("cannot stat exceptions dir: %w", err)
	}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		var ex Exception
		if err := yaml.Unmarshal(data, &ex); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if ex.SchemaVersion != "1" {
			return fmt.Errorf("%s: unsupported schema_version %q (expected %q)", path, ex.SchemaVersion, "1")
		}
		ex.SourcePath = path
		key := ExceptionKey{
			Image: NormaliseImage(ex.Product.Image),
			CVE:   ex.Vulnerability.ID,
		}
		if existing, dup := out[key]; dup {
			return fmt.Errorf("duplicate exception for image=%s cve=%s: %s and %s",
				key.Image, key.CVE, existing.SourcePath, path)
		}
		out[key] = ex
		return nil
	})
	return out, err
}
