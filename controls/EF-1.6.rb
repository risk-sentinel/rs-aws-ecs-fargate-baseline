# encoding: UTF-8

control "EF-1.6" do
  title "Task images must have an attached SBOM"
  desc "Each container image must carry a Software Bill of Materials "\
       "(SPDX/CycloneDX) as an OCI referrer, so its components are inventoried for "\
       "vulnerability and supply-chain analysis. Evaluated for digest-pinned task "\
       "images."
  desc  'check', "
    For each in-scope Fargate task image referenced as an ECR image by digest, look for an SBOM in the image's own region and registry: a cosign `sha256-<digest>.att` or `.sbom` tag, or an OCI referrer whose artifact type names SPDX, CycloneDX or an attestation envelope (cosign attestation, DSSE, in-toto).

    If none is found and one of those lookups failed, the control fails as undetermined rather than reporting no SBOM. Images outside ECR, or referenced by tag alone (see EF-1.1), are reported as skipped.
  "
  desc  'fix', "
    Generate an SBOM in the build pipeline (for example `syft <image> -o cyclonedx-json`) and attach it to the image digest as an OCI referrer, for example with `cosign attach sbom` or `oras attach --artifact-type application/vnd.cyclonedx+json`. Redeploy from that digest.
  "
  tag severity:              "medium"
  tag severity_source:       "unassessed"
  tag nist:                  ['SR-4']
  tag nist_r4_unmapped:      ['SR-4']
  tag cci:                   ['CCI-005096']
  tag local_number:          "EF-1.6"
  tag srg:                   "SRG-APP-000131-CTR-000285"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  images = task_image_refs
  impact 0.5
  impact 0.0 if images.empty?
  only_if("No resolvable ECR task images") { !images.empty? }

  unassessable_images(need_digest: true).each do |raw, why|
    describe "Image #{raw}" do
      skip "Not assessed: #{why}."
    end
  end

  images.each do |ref|
    next unless ref[:repo] && ref[:digest]
    img = aws_ecr_image(repository_name: ref[:repo], image_digest: ref[:digest],
                        region: ref[:region], registry_id: ref[:registry_id])
    # Whether we could tell, before what we found: a failed lookup must not
    # read as a missing sbom.
    determined = img.sbom_determined?
    errors = img.lookup_errors
    describe "SBOM lookup for #{ref[:repo]}@#{ref[:digest][0, 19]}" do
      it("can be determined") { expect(determined).to eq(true), "lookups failed: #{errors}" }
    end
    next unless determined

    describe img do
      it { should have_sbom }
    end
  end
end
