# rs-aws-ecs-fargate-baseline

[![Quality gate](https://sonarcloud.io/api/project_badges/quality_gate?project=risk-sentinel_aws-ecs-fargate-baseline)](https://sonarcloud.io/summary/new_code?id=risk-sentinel_aws-ecs-fargate-baseline)

InSpec / CINC Auditor profile validating an **AWS ECS Fargate** workload — 58
controls across task-definition hardening, image provenance, network placement,
load-balancer TLS, IAM role scoping, logging and tagging.

No CIS Benchmark or DISA STIG covers ECS Fargate as a subject. Controls are
anchored to **NIST 800-53 r5** (primary), **AWS Foundational Security Best
Practices**, **NIST SP 800-190** (container security), and DISA SRG container
CCI anchors where they apply. The derivation is in
[`PROVENANCE.md`](PROVENANCE.md) — read it before adopting this as evidence,
because a bespoke baseline is only as good as its stated basis.

Targets **AWS Commercial** and **AWS GovCloud (non-DoD)**.

---

## Quickstart

```bash
git clone https://github.com/risk-sentinel/rs-aws-ecs-fargate-baseline
cd rs-aws-ecs-fargate-baseline

cp inputs/example.yml inputs/mine.yml     # then edit — see Inputs below
cinc-auditor vendor . --overwrite

cinc-auditor exec . -t aws:// \
  --input-file inputs/mine.yml \
  --reporter cli json:results.json
```

`--input-file` is **not optional**, and for this profile one input in particular
changes what gets assessed — see `tls_termination` below.

### Credentials

Standard AWS credential resolution. Read-only across the Fargate surface:

```
ecs:List*  ecs:Describe*        ecr:Describe*  ecr:GetRepositoryPolicy
ec2:DescribeSubnets  ec2:DescribeRouteTables  ec2:DescribeSecurityGroups
elasticloadbalancing:Describe*  acm:DescribeCertificate
iam:GetRole  iam:GetRolePolicy  iam:ListAttachedRolePolicies
logs:DescribeLogGroups  guardduty:List*  guardduty:Get*
```

### What a first run looks like

Against a real Fargate deployment:

**58 controls, 77 results — roughly 49 passed / 17 failed / 11 skipped.**

If you see far fewer, that is the signal to investigate. A run that assessed
nothing exits 0 and looks clean.

---

## Inputs

Fully documented in [`inputs/example.yml`](inputs/example.yml).

| Group | Inputs |
|---|---|
| **Required** | `aws_partition` |
| **Terminate layer** | `tls_termination`, `alb_strong_ssl_policies` |
| **Scoping** | `scan_regions` |
| **Thresholds** | `require_image_digest_pinning`, `max_image_finding_severity`, `cert_expiry_warning_days`, `min_log_retention_days`, `allowed_added_capabilities` |
| **Allow-lists** | `trusted_image_registries`, `ecs_exec_allowed_services`, `required_tag_keys` |
| **Attestation** | `inherited_evidence_uri`, the `*_base` URIs, the two staleness windows |

**`tls_termination` is the input to get right first.** TLS is validated wherever
it actually terminates — at the load balancer (`alb`, the common Fargate shape),
in the container (`task`), or nowhere in this boundary (`none`). Declaring it
wrong means reading a column of failures for something another layer is doing
correctly.

**`allowed_added_capabilities` deserves a second look.** The default permits only
`NET_BIND_SERVICE`, which lets a container bind a low port without running as
root. Every addition widens container-escape blast radius, so each one should be
a decision rather than a convenience.

---

## Controls

58 controls across eight families:

| Family | Assesses |
|---|---|
| Task definition | non-root user, read-only root filesystem, no privileged mode, bounded cpu/memory, dropped capabilities |
| Image provenance | digest pinning, trusted registries, ECR scan-on-push and finding severity |
| Network | `awsvpc` mode, private subnets with no default route to an internet gateway, security-group ingress |
| TLS | load-balancer listener policy and certificate expiry, or in-task termination |
| IAM | task and execution role scoping, no wildcard actions, role-policy document parsing |
| Secrets | `secrets[]` from Secrets Manager / SSM rather than plaintext `environment[]` |
| Logging | log driver configured and log-group retention |
| Tagging | governance tags on cluster, service and task definition |

---

## Producing evidence

A `--reporter cli` run tells you the answer. It does not produce something an
assessor can trace back to what was assessed, when, by whom, or from which
scanner output. For that, use the CI templates — the whole pipeline, in YAML
with no helper scripts behind it:

**GitHub**

```yaml
jobs:
  evidence:
    uses: risk-sentinel/rs-aws-ecs-fargate-baseline/.github/workflows/exec-evidence.yml@main
    with:
      target: my-fargate-boundary
      profile_name: rs-aws-ecs-fargate-v1r1
      profile_version: "0.1.0"
    secrets:
      AWS_ROLE_ARN: ${{ secrets.AWS_ROLE_ARN }}
```

**GitLab**

```yaml
include:
  - project: risk-sentinel/rs-aws-ecs-fargate-baseline
    file: /ci/gitlab/exec-evidence.yml
    inputs:
      target: my-fargate-boundary
      profile_name: rs-aws-ecs-fargate-v1r1
      profile_version: "0.1.0"
```

An `include:` brings YAML and nothing else, which is why the logic lives in the
YAML rather than in a script an including project would never receive. The
templates are carried in this repository on purpose: clone it or include it and
you have the entire pipeline, with nothing else to install.

### The order, and why it is that order

```
create passthrough -> execute -> convert (gate) -> apply -> label (gate)
                   -> validate (gate) -> display
```

The audit record is built **before** the scan, because that is when the honest
start time and the pipeline provenance are known. Only finish time, the artifact
digest and the outcome counts are added afterwards.

### Two artifacts

| artifact | shape | for |
|---|---|---|
| `results.final.json` | HDF v3 `baselines[]` | authoritative evidence — schema-validated, carries the audit record and typed target components, feeds `hdf convert --to oscal-sar` |
| `results-heimdall.json` | InSpec exec-json `profiles[]` | loading into Heimdall |

The Heimdall artifact is a **copy, not a conversion**. Tested against a live
Heimdall: every `profiles[]` variant loads, including the output of both
`--to hdf@1` and `--to hdf@2`; only the `baselines[]` v3 document is refused. So
the choice is fidelity, and every conversion path drops `resource_params` from
each result plus `depends` / `status` / `status_message` from the profile.
Copying what cinc-auditor already wrote loses nothing.

**Do not reach for `hdf convert --to hdf@2`.** The `hdf@N` namespace was
renumbered between hdf-libs 3.4.1 and 3.5.1 — on 3.4.1 it emits `baselines[]`,
on 3.5.1 `profiles[]` — so a pipeline pinned to it silently changes artifact
across an image bump. On 3.5.1, `@1` and `@2` are byte-identical.

### Three gates, each of which has failed silently in this estate

- `hdf convert` without `--no-validate`
- `hdf label` followed by `hdf label show | grep '^Component:'` — `label set`
  prints `Labels written` and writes a byte-identical file when the document has
  no components
- `hdf validate`

The exec step additionally fails the job on a missing or **zero-result**
artifact. A run that assessed nothing must not go green.

### The audit record

Written on every run — clean, failed, findings or none. Target, scan window,
scanner, profile and version, pipeline provenance, actor, converter, a sha256 of
the pre-conversion artifact, and outcome counts.

Two properties are deliberate: **absent is not empty** (an inapplicable field is
omitted, an undeterminable one is `null` with a reason), and the record **marks
which fields are corroborable** against systems the producer does not control.
An audit chain where every field is self-asserted is a story.

Schema authority: [dev-sec-ops-baseline#33](https://github.com/risk-sentinel/dev-sec-ops-baseline/issues/33).

---

## Consuming this profile

Depend on it rather than forking, so you get fixes:

```yaml
depends:
  - name: rs-aws-ecs-fargate-v1r1
    git: https://github.com/risk-sentinel/rs-aws-ecs-fargate-baseline.git
    tag: v0.1.5
```

Then `include_controls 'rs-aws-ecs-fargate-v1r1'` and supply your own inputs. Input overrides
reach the depended profile's controls, so your values win without editing
anything here.

## Contributing

Control logic changes belong here. `cinc-auditor check` only *loads* a profile —
it will not catch a resource that returns empty because an API call failed.
Anything touching `libraries/` needs a real `exec` against a real target before
it is trusted.

## License

Apache-2.0. See [LICENSE](LICENSE).
