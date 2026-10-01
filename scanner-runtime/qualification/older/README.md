# Older scanner source candidate

Stacked source review over PR49 under https://github.com/StackVista/stackstate/issues/717.
Exact action revisions and tool selection are in policy-families.json. Scanner
families A/B/D use Trivy 0.70.0 and Grype 0.112.0; C uses the newer generation.
The tools are common selections, but the historical VEX/error policy blocks differ
and must remain at their original action pins. This source change updates no caller.

Complete original trees add Trivy 0.70.0, Grype 0.112.0, Syft 1.44.0 and Helm
3.20.2. Independently selected OpenVEX 0.2.7/0.2.8 and other exact owner trees
are reused only where original module selections match. Import-only backports
retain original API/Node boundaries, assets/licenses/generated files and fixtures.
Executable root replacements select actual owning sources, not parser identities.
The original Go minima remain 1.25.8 for both scanners/Syft and 1.25.0 for Helm.

The separate older workflow targets scanner-runtime-yaml so the stacked PR runs
native qualification instead of silently skipping main-only checks. Builds are
serial, use the same signature-verified BCI builder, retain JSONv2/linker settings,
and upload native amd64/arm64 branch artifacts with provenance and OIDC manifests.
No loader, consumer adoption, stable release or publication is authorized here.

Source inventory and native binary qualification are required before declaring
this generation adoptable. Existing newer PR49 qualification stays separate.
