# Provenance — `rs-aws-ecs-fargate-baseline`

## What this profile is

A **bespoke, Risk Sentinel–authored** security baseline for AWS **ECS on Fargate** — there is
no single published benchmark for Fargate task/service configuration, so every control is
anchored to a stack of federal + AWS authoritative sources, documented here so each check is
defensible in an assessment. 58 controls across 12 families (EF‑1…EF‑12); each carries a
`tag nist:` (NIST 800‑53 Rev 5), a DISA `tag cci:` + `tag srg:` (Container Platform SRG), and,
where an AWS‑native control exists, a `tag fsbp:`.

## Authoritative sources

| Key | Source | Role here |
|---|---|---|
| **NIST 800-53r5** | SP 800-53 Rev 5 control catalog | The control each check maps to (`tag nist:`) — AC / CM / SC / SI / AU / IA families. |
| **DISA Container Platform SRG** | DISA Container Platform Security Requirements Guide | The container-specific hardening requirements — `tag cci:` (CCI-*) + `tag srg:` (SRG-APP-*-CTR-*). Primary DoD anchor. |
| **NIST 800-190** | SP 800-190 Application Container Security Guide | The container-security framework the whole profile addresses (image, runtime, orchestrator, secrets, network isolation). |
| **AWS FSBP** | AWS Foundational Security Best Practices (Security Hub) | The AWS-native controls — `tag fsbp:` (ECS.*, ELB.*, ECR.1, ACM.1). |

Some controls also cross-reference CIS (`tag cis_source:`) where a CIS Docker/benchmark control
is analogous; CIS is a *supporting* reference, not the basis.

## Control-family provenance

| Family | Verifies | NIST 800-53r5 | DISA SRG-CTR / CCI | FSBP | Rationale (risk addressed) |
|---|---|---|---|---|---|
| **EF-1** Image integrity | Digest-pinned images; trusted registries | CM-2 (2), CM-8, CM-7, SI-7 | SRG-APP-000131-CTR-000285 · CCI-000366 | ECR.1 | A mutable tag or untrusted registry lets a tampered image run — supply-chain integrity. |
| **EF-2** Container privilege | Not privileged; runs as non-root | AC-6 | SRG-APP-000243-CTR-000595 · CCI-000056/002113 | ECS.4 | Privileged/root containers defeat isolation — least privilege. |
| **EF-3** Secrets handling | No plaintext env secrets; Secrets Manager/SSM ARNs | IA-5 (1), CM-6 | SRG-APP-000038-CTR-000105 · CCI-000389 | ECS.8 | Plaintext env vars leak into logs, task defs, and the console — protect authenticators. |
| **EF-4** IAM separation | Task role ≠ execution role; no wildcard action/resource | AC-5, AC-6 | SRG-APP-000342-CTR-000775 · CCI-002233 | — | Conflated/over-broad roles break separation of duties + least privilege. |
| **EF-5** Network isolation | `awsvpc` mode; no auto-assigned public IP | SC-7, AC-3 | SRG-APP-000039-CTR-000110 · CCI-001097 | ECS.5 | Shared/public networking erases the task boundary — boundary protection. |
| **EF-6** Runtime isolation | No host-network privileged; no host PID namespace | AC-6, CM-7, SC-39 | SRG-APP-000243-CTR-000595 | — | Host namespace sharing lets a container see/affect the host + peers — process isolation. |
| **EF-7** ECS Exec | Disabled by default; when on, audited + KMS-encrypted | AC-17 (2), AC-6 (9), AU-12, SC-28 | SRG-APP-000033-CTR-000095 · CCI-000067 | — | Interactive exec is a remote-access path into the workload — control + audit it. |
| **EF-8** Logging | Per-container log config; Container Insights | AU-2, AU-12 | SRG-APP-000510-CTR-001330 · CCI-000011/000123 | ECS.9 | No log config = no audit evidence for that container. |
| **EF-9** Inherited (AWS-managed) | Fargate host OS/kernel hardening; runtime-engine integrity | CM-6, SI-2, SC-39, SI-7 | CCI-000366/002605/001084 | — | Shared-responsibility controls **inherited from AWS** — evidenced (Fargate is managed), not host-tested. |
| **EF-10** Detection | GuardDuty Runtime Monitoring for ECS; account Container Insights default | SI-4, AU-6 (3), CA-7 | CCI-001253/002661/000130 | — | Runtime threat detection + continuous monitoring across the account. |
| **EF-11** Ingress TLS | Internet-facing ALB HTTPS listener; strong TLS policy | SC-8, SC-8 (1) | SRG-APP-000439-CTR-001070 · CCI-002418/002421 | ELB.2 | Cleartext ingress exposes data in transit — transmission confidentiality. |
| **EF-12** Reverse-proxy TLS | TLS termination wired where declared; ingress inventory | SC-8, SC-8 (1), SC-13, CM-8 | SRG-APP-000439-CTR-001070 | ACM.1 | Validate TLS at the layer where it actually terminates (proxy/sidecar), not just the ALB. |

## Notes

- **Granularity:** the table is per **family** (EF‑N); the 58 individual controls (EF‑N.n) each
  carry the authoritative `tag nist:` / `tag cci:` / `tag srg:` / `tag fsbp:` — those tags are the
  per-control cross-reference for OSCAL/Heimdall rollup.
- **EF-9 is inherited** (AWS shared-responsibility): these Pass with the AWS attestation/evidence
  (Fargate is a managed runtime), they are not host-level tested
  (AWS shared-responsibility inheritance).
- **Terminate-layer TLS** (EF‑11/EF‑12): TLS is validated wherever it terminates — the ALB *and*
  a reverse-proxy/sidecar — per a per-profile termination input.
- Keep this doc in sync when controls are added/removed or re-anchored.

_Closes #6._
