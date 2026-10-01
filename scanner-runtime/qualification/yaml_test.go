package qualification

import (
	"bytes"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

type custom struct{ Value string }

func (c *custom) UnmarshalYAML(n *yaml.Node) error { return n.Decode(&c.Value) }
func (c custom) MarshalYAML() (any, error)         { return c.Value, nil }

var _ yaml.Unmarshaler = (*custom)(nil)
var _ yaml.Marshaler = custom{}

func TestNodeCustomAliasRoundtrip(t *testing.T) {
	var value struct {
		First  custom `yaml:"first"`
		Second custom `yaml:"second"`
	}
	if err := yaml.Unmarshal([]byte("first: &value preserved\nsecond: *value\n"), &value); err != nil {
		t.Fatal(err)
	}
	if value.First.Value != "preserved" || value.Second.Value != "preserved" {
		t.Fatalf("custom/alias dispatch lost: %+v", value)
	}
	data, err := yaml.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var roundtrip struct {
		First  custom `yaml:"first"`
		Second custom `yaml:"second"`
	}
	if err := yaml.Unmarshal(data, &roundtrip); err != nil {
		t.Fatal(err)
	}
	if value != roundtrip {
		t.Fatalf("roundtrip differs: %q", data)
	}
}

func TestMalformedAndDuplicateMappings(t *testing.T) {
	for _, input := range []string{"key: [unterminated", "key: first\nkey: second\n", "key: *missing\n"} {
		var value map[string]any
		if err := yaml.Unmarshal([]byte(input), &value); err == nil {
			t.Fatalf("accepted invalid YAML: %q", input)
		}
	}
}

func TestStrictDecoderAndDocumentStream(t *testing.T) {
	var value struct {
		Name string `yaml:"name"`
	}
	decoder := yaml.NewDecoder(strings.NewReader("name: first\n---\nname: second\n"))
	decoder.KnownFields(true)
	if err := decoder.Decode(&value); err != nil || value.Name != "first" {
		t.Fatalf("first document: %+v %v", value, err)
	}
	if err := decoder.Decode(&value); err != nil || value.Name != "second" {
		t.Fatalf("second document: %+v %v", value, err)
	}
	decoder = yaml.NewDecoder(bytes.NewBufferString("unknown: value\n"))
	decoder.KnownFields(true)
	if err := decoder.Decode(&value); err == nil {
		t.Fatal("strict decoder accepted unknown field")
	}
}
