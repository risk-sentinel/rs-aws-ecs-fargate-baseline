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

The union of each family's control tags, generated from `controls/` — regenerate with
`python3 tools/render_provenance.py`; `--check` fails when this block is stale.

<!-- BEGIN GENERATED: family anchors (tools/render_provenance.py) -->
| Family | Controls | NIST 800-53r5 (`tag nist`) | DISA SRG-CTR (`tag srg`) | CCI (`tag cci`) | FSBP (`tag fsbp`) |
|---|---|---|---|---|---|
| **EF-1** | 7 (7 implemented): EF-1.1…EF-1.7 | CM-2 (2), CM-5 (6), CM-7 (5) (b), CM-7 a, RA-5 a, SI-2 a, SI-7 (6), SI-7 a, SR-4 | SRG-APP-000131-CTR-000285, SRG-APP-000141-CTR-000320, SRG-APP-000414-CTR-001010, SRG-APP-000456-CTR-001125 | CCI-000302, CCI-000381, CCI-001054, CCI-001225, CCI-001499, CCI-001774, CCI-002704, CCI-002716, CCI-005096 | ECR.1 |
| **EF-2** | 9 (9 implemented): EF-2.1…EF-2.10 | AC-6, AC-6 (8), CM-7 a, CM-7 b, SC-6, SI-13 (4) (a), SI-13 b | SRG-APP-000133-CTR-000290, SRG-APP-000133-CTR-000295, SRG-APP-000142-CTR-000330, SRG-APP-000243-CTR-000595, SRG-APP-000342-CTR-000775, SRG-APP-000435-CTR-001070 | CCI-000225, CCI-000381, CCI-000382, CCI-001318, CCI-001326, CCI-002233, CCI-002392 | ECS.4, ECS.5, ECS.20 |
| **EF-3** | 2 (2 implemented): EF-3.1…EF-3.2 | CM-6 b, IA-5 (7), SC-28 | SRG-APP-000038-CTR-000105 | CCI-000366, CCI-001199, CCI-004069 | ECS.8 |
| **EF-4** | 4 (4 implemented): EF-4.1…EF-4.4 | AC-5 b, AC-6, SC-28 | SRG-APP-000033-CTR-000095, SRG-APP-000342-CTR-000775 | CCI-000225, CCI-001199, CCI-002220 | ECS.8 |
| **EF-5** | 4 (4 implemented): EF-5.1…EF-5.5 | SC-7 a, SC-7 c | SRG-APP-000039-CTR-000110, SRG-APP-000142-CTR-000325 | CCI-001097, CCI-001098 | ECS.2 |
| **EF-6** | 5 (5 implemented): EF-6.1…EF-6.6 | AC-6, CM-7 b, SC-8, SC-8 (1), SC-28, SC-28 (1), SC-39, SI-2 a | SRG-APP-000243-CTR-000595, SRG-APP-000429-CTR-001060, SRG-APP-000431-CTR-001065, SRG-APP-000439-CTR-001080, SRG-APP-000456-CTR-001125 | CCI-000225, CCI-000382, CCI-001199, CCI-001225, CCI-002418, CCI-002421, CCI-002476, CCI-002530 | ECS.3, ECS.10 |
| **EF-7** | 2 (2 implemented): EF-7.1…EF-7.2 | AC-17 (2), AC-17 b, AU-12 a, AU-12 c, CM-7 b | SRG-APP-000033-CTR-000095, SRG-APP-000092-CTR-000165 | CCI-000065, CCI-000068, CCI-000169, CCI-000172, CCI-000382 | — |
| **EF-8** | 6 (6 implemented): EF-8.1…EF-8.7 | AU-4, AU-4 (1), AU-6 (3), AU-9 (2), AU-11, AU-12 a, AU-12 c, CM-8 a 1, CP-10 | SRG-APP-000357-CTR-000800, SRG-APP-000358-CTR-000805, SRG-APP-000510-CTR-001330 | CCI-000153, CCI-000167, CCI-000169, CCI-000172, CCI-001348, CCI-001849, CCI-001851, CCI-003962, CCI-004028 | ECS.9, ECS.12, ECS.13/14/15 |
| **EF-9** | 6 (6 inherited): EF-9.1…EF-9.6 | AC-3, AU-12 a, AU-12 c, CM-5, CM-6 b, IA-2, IA-5 g, IA-7, SC-13 b, SC-39, SI-2 c, SI-7 | — | CCI-000169, CCI-000172, CCI-000183, CCI-000213, CCI-000345, CCI-000366, CCI-000764, CCI-000803, CCI-002450, CCI-002530, CCI-002605, CCI-002703 | — |
| **EF-10** | 4 (1 alternative, 3 implemented): EF-10.1…EF-10.4 | AU-6 (3), CA-7, CM-6 b, SI-2 c, SI-4 (2), SI-4 a 1 | — | CCI-000153, CCI-000274, CCI-000366, CCI-001260, CCI-002605, CCI-002641 | — |
| **EF-11** | 7 (7 implemented): EF-11.1…EF-11.7 | AU-12 a, AU-12 c, CP-10, SC-8, SC-8 (1), SC-13 b, SC-17 a, SI-10 | SRG-APP-000092-CTR-000165, SRG-APP-000251-CTR-000600, SRG-APP-000439-CTR-001070, SRG-APP-000516-CTR-001325, SRG-APP-000516-CTR-001335 | CCI-000169, CCI-000172, CCI-001159, CCI-001310, CCI-002418, CCI-002421, CCI-002450, CCI-004028 | ACM.1, ELB.1, ELB.2, ELB.4, ELB.5, ELB.6, ELB.17 |
| **EF-12** | 2 (2 implemented): EF-12.1…EF-12.2 | CM-8 a 1, SC-8, SC-8 (1) | SRG-APP-000439-CTR-001070 | CCI-002418, CCI-002421, CCI-003962 | — |

58 controls across 12 families.
<!-- END GENERATED: family anchors -->

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
