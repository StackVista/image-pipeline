package grypevex

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type repositoryConfig struct {
	Repositories []struct {
		Name                 string `yaml:"name"`
		Enabled              bool   `yaml:"enabled"`
		SkipInvalidDocuments bool   `yaml:"skip_invalid_documents"`
	} `yaml:"repositories"`
}

type index struct {
	Packages []struct {
		Format   string `json:"format"`
		Location string `json:"location"`
	} `json:"packages"`
}

type Prepared struct {
	Documents []string
	OpenVEX   int
	CSAF      int
	Warnings  []error
}

func Prepare(cacheDir, configPath, outputDir string) (Prepared, []error) {
	var result Prepared
	var problems []error
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return result, []error{err}
	}
	var config repositoryConfig
	if err := yaml.Unmarshal(configData, &config); err != nil {
		return result, []error{fmt.Errorf("read VEX repository configuration: %w", err)}
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return result, []error{err}
	}
	seen := make(map[string]bool)
	for _, repository := range config.Repositories {
		if !repository.Enabled {
			continue
		}
		if repository.Name == "." || repository.Name == ".." ||
			filepath.Base(repository.Name) != repository.Name ||
			strings.ContainsAny(repository.Name, "/\\\r\n") || repository.Name == "" {
			problems = append(problems, fmt.Errorf("invalid VEX repository name %q", repository.Name))
			continue
		}
		root := filepath.Join(cacheDir, repository.Name, "0.1")
		indexPath := filepath.Join(root, "index.json")
		if _, err := os.Stat(indexPath); os.IsNotExist(err) {
			root = filepath.Join(root, "vexhub-main")
			indexPath = filepath.Join(root, "index.json")
		}
		rawIndex, err := os.ReadFile(indexPath)
		if err != nil {
			problems = append(problems, fmt.Errorf("repository %s: %w", repository.Name, err))
			continue
		}
		var entries index
		if err := json.Unmarshal(rawIndex, &entries); err != nil {
			problems = append(problems, fmt.Errorf("repository %s index: %w", repository.Name, err))
			continue
		}
		if len(entries.Packages) == 0 {
			problems = append(problems, fmt.Errorf("repository %s has no indexed VEX documents", repository.Name))
			continue
		}
		documentCount := len(result.Documents)
		rejected := func(err error) {
			if repository.SkipInvalidDocuments {
				result.Warnings = append(result.Warnings, fmt.Errorf("repository %s: skipping document: %w", repository.Name, err))
			} else {
				problems = append(problems, err)
			}
		}
		for _, entry := range entries.Packages {
			path, err := documentPath(root, entry.Location)
			if err != nil {
				problems = append(problems, fmt.Errorf("repository %s: %w", repository.Name, err))
				continue
			}
			if seen[path] {
				continue
			}
			seen[path] = true
			data, err := os.ReadFile(path)
			if err != nil {
				problems = append(problems, err)
				continue
			}
			switch entry.Format {
			case "", "openvex":
				var document struct {
					Context    string             `json:"@context"`
					Statements *[]json.RawMessage `json:"statements"`
				}
				if err := json.Unmarshal(data, &document); err != nil ||
					!strings.HasPrefix(document.Context, "https://openvex.dev/ns") || document.Statements == nil {
					rejected(fmt.Errorf("%s: invalid OpenVEX document", path))
					continue
				}
				result.OpenVEX++
			case "csaf":
				converted, err := Convert(data)
				if err != nil {
					rejected(fmt.Errorf("%s: %w", path, err))
					continue
				}
				filename := fmt.Sprintf("%x.openvex.json", sha256.Sum256([]byte(path)))
				path, err = filepath.Abs(filepath.Join(outputDir, filename))
				if err == nil && strings.ContainsAny(path, "\r\n") {
					err = fmt.Errorf("converted VEX document path contains a line break")
				}
				if err == nil {
					err = os.WriteFile(path, converted, 0o644)
				}
				if err != nil {
					problems = append(problems, err)
					continue
				}
				result.CSAF++
			default:
				rejected(fmt.Errorf("%s: unsupported VEX format %q", path, entry.Format))
				continue
			}
			result.Documents = append(result.Documents, path)
		}
		if len(result.Documents) == documentCount {
			problems = append(problems, fmt.Errorf("repository %s has no usable indexed VEX documents", repository.Name))
		}
	}
	if len(result.Documents) == 0 {
		problems = append(problems, fmt.Errorf("no indexed VEX documents were prepared for Grype"))
	}
	return result, problems
}

func documentPath(root, location string) (string, error) {
	if location == "" || filepath.IsAbs(location) || strings.ContainsAny(location, "\\\r\n") {
		return "", fmt.Errorf("invalid VEX document location %q", location)
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	realPath, err := filepath.EvalSymlinks(filepath.Join(realRoot, filepath.FromSlash(location)))
	if err != nil {
		return "", err
	}
	if strings.ContainsAny(realPath, "\r\n") {
		return "", fmt.Errorf("resolved VEX document location contains a line break: %q", location)
	}
	relative, err := filepath.Rel(realRoot, realPath)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("VEX document location escapes repository: %q", location)
	}
	return filepath.Abs(realPath)
}
