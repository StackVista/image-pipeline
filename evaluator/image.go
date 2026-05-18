package main

import "strings"

// NormaliseImage strips tag and/or digest from an OCI image reference,
// returning the registry/repository name. Handles refs with embedded
// registry ports correctly (e.g. localhost:5000/foo/bar:v1 -> localhost:5000/foo/bar).
func NormaliseImage(ref string) string {
	slash := strings.LastIndex(ref, "/")
	tail := ref[slash+1:]
	if i := strings.IndexAny(tail, "@:"); i >= 0 {
		return ref[:slash+1+i]
	}
	return ref
}
