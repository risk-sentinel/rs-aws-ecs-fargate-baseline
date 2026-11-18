# Provenance — `rs-aws-ecs-fargate-baseline`

## What this profile is

A **bespoke, Risk Sentinel–authored** security baseline for AWS **ECS on Fargate** — there is
no single published benchmark for Fargate task/service configuration, so every control is
anchored to a stack of federal + AWS authoritative sources, documented here so each check is
defensible in an assessment. 58 controls across 12 families (EF‑1…EF‑12; `EF` = ECS Fargate);
each carries a `tag nist:` (NIST 800‑53 Rev 5) and a DISA `tag cci:`, most a `tag srg:`
(Container Platform SRG), and, where an AWS‑native control exists, a `tag fsbp:`.

## Authoritative sources

| Key | Source | Role here |
|---|---|---|
| **NIST 800-53r5** | SP 800-53 Rev 5 control catalog | The control part each check maps to (`tag nist:`) — AC / AU / CA / CM / CP / IA / RA / SC / SI / SR. |
| **DISA CCI list** | DISA Control Correlation Identifier list | `tag cci:`. `tag nist:` is exactly the union of each control's CCIs' Rev 5 parts, checked by `tools/lint_control_tags.py`. |
| **DISA Container Platform SRG** | DISA Container Platform Security Requirements Guide | The container-specific hardening requirements — `tag srg:` (SRG-APP-*-CTR-*). Primary DoD anchor. |
| **NIST 800-190** | SP 800-190 Application Container Security Guide | The container-security framework the whole profile addresses (image, runtime, orchestrator, secrets, network isolation). |
| **AWS FSBP** | AWS Foundational Security Best Practices (Security Hub) | The AWS-native controls — `tag fsbp:` (ECS.*, ELB.*, ECR.1, ACM.1). |

Some controls also cross-reference CIS (`tag cis_source:`) where a CIS Docker/benchmark control
is analogous; CIS is a *supporting* reference, not the basis.

## Control families

| Family | Verifies | Rationale (risk addressed) |
|---|---|---|
| **EF-1** Image supply chain | Digest-pinned images from trusted registries; ECR scan-on-push and tag immutability; a signature (cosign tag, OCI referrer or AWS-native); an attached SBOM; no findings above the tolerated severity | A mutable, unscanned or unsigned image lets tampered or vulnerable code run — supply-chain integrity. |
| **EF-2** Container hardening | Not privileged; non-root; read-only root filesystem; ALL capabilities dropped with an allowlist and no escalating adds; CPU/memory limits; ulimits; a health check; no privileged ports | Privileged, root or unbounded containers defeat isolation and starve neighbours — least privilege and resource protection. |
| **EF-3** Secrets handling | No plaintext secrets in `environment[]`; `secrets[]` reference Secrets Manager / SSM ARNs | Plaintext env vars leak into logs, task definitions and the console — protect authenticators. |
| **EF-4** IAM roles | Task role distinct from execution role; no wildcard action on wildcard resource, no wildcard execution-role actions; no long-lived AWS credentials in task definitions | Conflated or over-broad roles and embedded keys break separation of duties and least privilege. |
| **EF-5** Network isolation | `awsvpc` mode; no auto-assigned public IP; tasks in private subnets (no default route to an internet gateway); no 0.0.0.0/0 security-group ingress | Shared or public networking erases the task boundary — boundary protection. |
| **EF-6** Runtime isolation and platform | Host-network task definitions not privileged/root; no host PID namespace; latest Fargate platform version; ephemeral storage encrypted with a CMK; EFS volumes encrypted in transit | Host namespace sharing, stale platforms and unencrypted task storage weaken the isolation boundary — process isolation and data protection. |
| **EF-7** ECS Exec | Disabled except on allowed services; where enabled, sessions audited and KMS-encrypted | Interactive exec is a remote-access path into the workload — control and audit it. |
| **EF-8** Logging, tagging and resilience | Per-container log configuration shipped off-host; Container Insights; log-group retention; required governance tags; deployment circuit breaker | Missing or short-lived logs leave no audit evidence; untagged resources escape inventory; a failed deploy without a circuit breaker stays in place. |
| **EF-9** Inherited (AWS-managed) | Fargate host OS/kernel; container runtime engine; ECS/Fargate control plane; IAM/STS identity store; platform audit infrastructure; FIPS-validated cryptographic modules | Shared-responsibility controls **inherited from AWS** — evidenced (Fargate is managed), not host-tested. |
| **EF-10** Detection and currency | GuardDuty Runtime Monitoring with Fargate agent management in every region holding a cluster; account-level Container Insights default; `runtimePlatform` pinned; base images current (EF-10.4, by attestation) | Runtime threat detection, continuous monitoring, and images that still receive fixes. |
| **EF-11** Ingress TLS (ALB) | Internet-facing ALBs offer HTTPS with a strong TLS policy and valid certificates; HTTP redirects to HTTPS; invalid headers dropped; access logging; deletion protection | Cleartext or weak ingress exposes data in transit, and unlogged ingress leaves no record — transmission confidentiality and audit. |
| **EF-12** Reverse-proxy TLS | TLS termination wired where declared; reverse-proxy/ingress container inventory | Validate TLS at the layer where it actually terminates (proxy/sidecar), not just the ALB. |

## Family anchors

The union of each family's `tag nist` / `tag srg` / `tag cci` / `tag fsbp` is in
[`docs/family-anchors.md`](docs/family-anchors.md), generated from `controls/` by
`tools/render_provenance.py`; `--check` fails when it is stale.

## Notes

- **Granularity:** the tables are per **family** (EF‑N); each of the 58 controls (EF‑N.n)
  carries its own `tag nist:` / `tag cci:` / `tag srg:` / `tag fsbp:`, and those per-control tags
  are what OSCAL and Heimdall roll up.
- **EF-9 is inherited** (AWS shared-responsibility): these pass with the AWS attestation and
  evidence (Fargate is a managed runtime); they are not host-level tested.
- **EF-10.4 is an alternative implementation:** base-image currency is evidenced by an attested
  policy rather than read from an API.
- **Terminate-layer TLS** (EF‑11/EF‑12): TLS is validated wherever it terminates — the ALB *and*
  a reverse-proxy/sidecar — per a per-profile termination input.
