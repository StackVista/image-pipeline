package main

import "testing"

func TestNormaliseImage(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		// Plain name, no tag, no digest, no registry.
		{"kafka", "kafka"},
		{"alpine:3.10", "alpine"},
		// Registry + path, no tag.
		{"quay.io/stackstate/kafka", "quay.io/stackstate/kafka"},
		// Registry + path + tag.
		{"quay.io/stackstate/kafka:v1.2.3", "quay.io/stackstate/kafka"},
		// Digest only.
		{"quay.io/stackstate/kafka@sha256:abc123", "quay.io/stackstate/kafka"},
		// Tag and digest.
		{"quay.io/stackstate/kafka:v1.2.3@sha256:abc123", "quay.io/stackstate/kafka"},
		// Registry with port — port stays in the canonical name.
		{"localhost:5000/foo/bar", "localhost:5000/foo/bar"},
		{"localhost:5000/foo/bar:v1", "localhost:5000/foo/bar"},
	}
	for _, c := range cases {
		if got := NormaliseImage(c.in); got != c.want {
			t.Errorf("NormaliseImage(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}
