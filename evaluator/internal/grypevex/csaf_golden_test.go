package grypevex

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	vex "github.com/openvex/go-vex/pkg/vex"
	"github.com/stretchr/testify/require"
)

func TestConvertGoldenFiles(t *testing.T) {
	inputs, err := filepath.Glob("testdata/conversion/*/input.csaf.json")
	require.NoError(t, err)
	require.NotEmpty(t, inputs, "conversion examples are missing")

	for _, inputPath := range inputs {
		directory := filepath.Dir(inputPath)
		t.Run(filepath.Base(directory), func(t *testing.T) {
			input, err := os.ReadFile(inputPath)
			require.NoError(t, err)
			expectedPath := filepath.Join(directory, "expected.openvex.json")
			errorPath := filepath.Join(directory, "expected-error.txt")
			expectedError, readErr := os.ReadFile(errorPath)

			actual, err := Convert(input)
			if readErr == nil {
				_, statErr := os.Stat(expectedPath)
				require.True(t, os.IsNotExist(statErr), "case must expect either output or an error")
				require.Error(t, err)
				require.Equal(t, strings.TrimSuffix(string(expectedError), "\n"), err.Error())
				require.Empty(t, actual, "rejected documents must not produce an output")
				t.Logf("%s → %s (rejected)", inputPath, errorPath)
				return
			}
			require.True(t, os.IsNotExist(readErr), "cannot read expected error: %v", readErr)
			require.NoError(t, err)
			expected, err := os.ReadFile(expectedPath)
			require.NoError(t, err)
			require.JSONEq(t, string(expected), string(actual), "output differs from %s", expectedPath)

			for name, data := range map[string][]byte{"expected": expected, "actual": actual} {
				document, err := vex.Parse(data)
				require.NoError(t, err, "%s OpenVEX document", name)
				require.NotEmpty(t, document.Statements)
				for i, s := range document.Statements {
					require.NoError(t, s.Validate(), "%s statement %d", name, i)
				}
			}
			t.Logf("%s → %s", inputPath, expectedPath)
		})
	}
}
