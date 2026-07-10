package main

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExceptionSchemaSupportsScannerSeverities(t *testing.T) {
	data, err := os.ReadFile("../schemas/exception.schema.json")
	require.NoError(t, err)

	var schema struct {
		Properties struct {
			Vulnerability struct {
				Properties struct {
					Severity struct {
						Enum []string `json:"enum"`
					} `json:"severity"`
				} `json:"properties"`
			} `json:"vulnerability"`
		} `json:"properties"`
	}
	require.NoError(t, json.Unmarshal(data, &schema))
	require.ElementsMatch(
		t,
		[]string{"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"},
		schema.Properties.Vulnerability.Properties.Severity.Enum,
	)
}
