# encoding: UTF-8

control "EF-1.6" do
  title "Task images must have an attached SBOM"
  desc "Each container image must carry a Software Bill of Materials (SPDX/CycloneDX) as "\
       "an OCI referrer, so its components are inventoried for vulnerability and "\
       "supply-chain analysis (SI-7/RA-5). Evaluated for digest-pinned task images."
  desc  'check', "
    For each in-scope Fargate task image referenced as an in-account ECR image by digest, list its OCI referrers (`ecr:ListImageReferrers`). At least one referrer must have an artifact or media type identifying an SBOM: SPDX, CycloneDX, in-toto or `sbom`. Images referenced by tag alone are skipped here and fail EF-1.1.
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

  images.each do |ref|
    next unless ref[:repo] && ref[:digest]
    describe aws_ecr_image(repository_name: ref[:repo], image_digest: ref[:digest]) do
      it { should have_sbom }
    end
  end
end
