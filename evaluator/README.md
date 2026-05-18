# evaluator

Go binary that applies exception policy to vulnerability scanner output
and produces a pass/fail decision plus a human-readable summary. Wraps
Trivy and Grype today; designed for multi-scanner via the `Scanner`
interface.

## What it does

Given:

- one or more scanner JSON reports (Trivy, Grype),
- an optional directory of exception YAML files (per-consumer policy),
- the image being scanned,

it:

1. Loads exceptions, indexed by `(image, CVE)` per the schema in
   `../schemas/exception.schema.json`.
2. Parses each scanner's JSON and normalises findings to an internal
   model so adding new adapters is one new file.
3. For each in-scope finding (default `HIGH,CRITICAL`), checks
   whether an exception for `(image, CVE)` exists and is unexpired.
4. Decides per finding:
   - **suppressed** — matched and unexpired
   - **expired** — matched but past expiry; gate fails
   - **unmanaged** — no matching exception
5. Returns an exit code based on `--mode`:
   - `gate` (default): exit 1 on any unmanaged or expired finding
   - `inform`: always exit 0; the summary is the deliverable
6. Prints a plain-text summary to stdout.

## File layout

| File | Responsibility |
|------|----------------|
| `main.go` | CLI entry, flag parsing, wiring |
| `exception.go` | Exception types, `ExceptionKey`, `LoadExceptions` |
| `finding.go` | `Finding`, `Scanner` interface, `DedupeFindings` |
| `trivy.go` | `TrivyScanner` — Trivy JSON adapter |
| `grype.go` | `GrypeScanner` — Grype JSON adapter |
| `evaluate.go` | `Evaluate`, `Decision`, `ExitCode`, mode constants |
| `summary.go` | `Summarise`, `Format` |
| `sarif.go` | `buildSARIF`, `writeSARIF` (SARIF 2.1.0 emission for GHAS) |
| `image.go` | `NormaliseImage` (strips tag/digest from OCI refs) |
| `*_test.go` | Tests adjacent to source |

## Build, test, run

From the repo root with mise installed:

```bash
mise run build              # builds bin/image-pipeline-evaluate
mise run test-evaluator     # go test ./...
mise run test               # all tests
mise run lint               # gofmt + go vet + zizmor
goreleaser release --snapshot --clean   # local snapshot build (writes ./dist/)
goreleaser check                        # validate .goreleaser.yml
```

Direct invocation against the bundled test fixture:

```bash
./bin/image-pipeline-evaluate \
    --trivy-json ./evaluator/testdata/trivy-kafka-fixture.json \
    --image quay.io/example/kafka:v1.2.3 \
    [--exceptions <dir>] \
    [--severity HIGH,CRITICAL] \
    [--mode gate|inform] \
    [--sarif <path>]
```

Exit codes:

- `0` — gate passes (or `--mode inform`)
- `1` — gate fails (unmanaged or expired finding in gate mode)
- `2` — usage / loader error

`--image` accepts any OCI ref; the tag and/or digest are stripped
before matching against exceptions.

## SARIF output

`--sarif <path>` writes a SARIF 2.1.0 document for upload to GitHub
Code Scanning (GHAS). Suppression decisions are preserved, not erased:

- **Suppressed by exception** — emitted as a SARIF result with a
  `suppressions[]` entry (`kind: "external"`, justification carrying
  the exception's status + reason, source path in properties). GHAS
  hides these from the default Code Scanning view but they remain in
  the audit trail.
- **Expired exception** — emitted as a *live* result with
  `properties["image-pipeline.status"] = "expired"`, so GHAS surfaces
  the lapse rather than silently passing.
- **Unmanaged** — emitted as a live result with no suppressions.

Severities map to SARIF level + GHAS `security-severity`:
CRITICAL→error/9.5, HIGH→error/8.0, MEDIUM→warning/5.0,
LOW→note/2.0. `partialFingerprints.primaryLocationLineHash` is a
SHA-256 of `(image, CVE, package, version)` so GHAS can dedupe the
same finding across runs.

## Adding a new scanner

The `Scanner` interface in `finding.go` is the only contract a new
adapter implements:

```go
type Scanner interface {
    Name() string
    Parse(io.Reader) ([]Finding, error)
}
```

Steps:

1. Add a new file (e.g. `snyk.go`) with a type satisfying `Scanner`.
2. Map the scanner's JSON fields onto `Finding`. Uppercase severity;
   set `SourceScanners` to `[]string{Name()}`.
3. Wire it into `main.go` (a flag for the scanner's JSON path; append
   parsed findings to the slice fed into `DedupeFindings`).
4. Add a `_test.go` mirroring `trivy_test.go`: `Name()`, `Parse()`
   against an inline JSON fixture, and (optionally) a real-world
   fixture under `testdata/`.

Identical findings reported by multiple scanners are merged by
`DedupeFindings`; the resulting `Finding.SourceScanners` carries all
reporting scanners (so a CVE found by both Trivy and Grype shows
`[grype,trivy]` in the summary).

## Releases

Tagged via SemVer (`vX.Y.Z`). Pushing a `v*` tag triggers
`.github/workflows/evaluator-release.yml`, which runs goreleaser to
publish linux/darwin × amd64/arm64 archives plus a `checksums.txt` to
the GitHub Release. The build embeds the tag into the binary via
`-ldflags "-X main.version=<tag>"`; the value flows through to the
SARIF document's `runs[0].tool.driver.version`.

For local validation before tagging, run
`goreleaser release --snapshot --clean` — produces the same archives
under `./dist/` without publishing.

## Related

- Exception schema: `../schemas/exception.schema.json`
- VEX repo config: `../vex/repository.yaml`
- Composite action that wires it up: `../.github/actions/scan-image/action.yml`
- CI workflow: `../.github/workflows/evaluator-ci.yml`
- Release workflow: `../.github/workflows/evaluator-release.yml`
- Release config: `../.goreleaser.yml`
