# CSAF → OpenVEX examples

Each directory pairs `input.csaf.json` with `expected.openvex.json`, or with
`expected-error.txt` when conversion must reject the document. Open the two
files side by side to inspect the conversion.

| Example | Input | Expected result |
|---|---|---|
| [Rancher MinIO](rancher-minio/) | Unchanged Rancher report: 24 vulnerability entries, 17 component relationships, multiple package versions and CVE/GO/GHSA aliases | 84 statements, each retaining the MinIO parent and exact component version |
| [Rancher ZooKeeper](rancher-zookeeper/) | Unchanged Rancher report containing a Jackson CVE and SUSE advisory identifiers | One image-scoped Jackson statement; unsupported SUSE identifiers are omitted |
| [Two images](two-images/) | Synthetic: the same CVE and Jackson version in two images, with different statuses | ZooKeeper is `not_affected`; the example service is `affected`, with remediation text and its latest date |
| [Grouped dispositions](grouped-dispositions/) | Synthetic: group-scoped flags, impact text and remediations; an entry without `cve`; fixed and investigating products | Ten statements preserving each image scope, both GHSA/GO aliases and all four supported statuses |
| [Unsafe relationship](unsafe-relationship/) | Synthetic: a relationship carries an additional image digest constraint | An explicit error and no output document |

The synthetic examples are test data, not security assessments.

## How to read the output

A CSAF status can reference a relationship ID. Follow that relationship's
`product_reference` to the component and `relates_to_product_reference` to its
parent. Their identification helpers provide the PURLs.

In OpenVEX, the parent PURL becomes `products[].@id`, and the component PURL
becomes `products[].subcomponents[].@id`. This preserves the assessment's scope
to a component inside a particular product.

For example, in `two-images`, `jackson-in-zookeeper` resolves to the ZooKeeper
image plus Jackson `2.22.0`. `jackson-in-example-service` resolves to a different
image plus the same Jackson version. The output keeps two separate statements
for `CVE-2099-0001`, with different statuses. The service's remediation text
does not become part of ZooKeeper's statement.

In `grouped-dispositions`, the groups contain relationship IDs. Each group
annotation applies only to its members. An input with GHSA and GO identifiers
produces statements for both identifiers even when it has no `cve` field.

CSAF-only descriptions, scores and notes are not copied into this compatibility
format. In particular, the ZooKeeper example documents the current omission of
`SUSE-SU-*` identifiers; it does not mean those source entries were absent.

## Run the comparison

From `evaluator/`:

```bash
go test ./internal/grypevex -run '^TestConvertGoldenFiles$' -v
```

The test reads the expected files as checked-in expectations. It compares the
complete JSON document, including metadata, identifiers, product scopes and
statement order. Object-key order and JSON whitespace do not affect comparison.
It also parses both outputs with `go-vex` and validates every statement.
Rejected examples must match their exact error and produce no output.

The output `@id` is `urn:csaf:` followed by the SHA-256 of the input's exact bytes.
Editing input whitespace therefore changes that ID even though the assessments
may remain identical.

To add an example, create another directory with an input and one expectation.
The test discovers all these directories automatically. Review expected-output
changes as behavior changes; the test does not regenerate expectations.

## Rancher source

The two Rancher inputs are byte-for-byte snapshots from
[`rancher/vexhub` at `e1193b1d0f47b6948ab1301367f28aa188e2bb5f`](https://github.com/rancher/vexhub/tree/e1193b1d0f47b6948ab1301367f28aa188e2bb5f):

- [MinIO source](https://github.com/rancher/vexhub/blob/e1193b1d0f47b6948ab1301367f28aa188e2bb5f/pkg/golang/github.com/minio/minio/scan.vex.json)
- [ZooKeeper source](https://github.com/rancher/vexhub/blob/e1193b1d0f47b6948ab1301367f28aa188e2bb5f/pkg/oci/quay.io/stackstate/zookeeper/scan.vex.json)

Tests use the local snapshots and require no hub downloads.
