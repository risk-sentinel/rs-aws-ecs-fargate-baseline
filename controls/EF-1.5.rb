# encoding: UTF-8

control "EF-1.5" do
  title "Task images must be cryptographically signed"
  desc "Container images must carry a verifiable signature (e.g., cosign/notation) "\
       "so their provenance and integrity can be attested before deployment. "\
       "Evaluated for digest-pinned task images; tag-only references are caught by "\
       "EF-1.1."
  desc  'check', "
    For each in-scope Fargate task image referenced as an ECR image by digest, look for a signature in the image's own region and registry, three ways: a cosign `sha256-<digest>.sig` tag in the repository; an OCI referrer whose artifact type is a cosign, Notation or Sigstore signature; or AWS-native signing (`ecr:DescribeImageSigningStatus`) with status `COMPLETE`. Any one passes.

    If none is found and one of those lookups failed, the control fails as undetermined, naming the failed lookup, rather than reporting the image unsigned. Images outside ECR, or referenced by tag alone (see EF-1.1), are reported as skipped.
  "
  desc  'fix', "
    Sign images in the build pipeline before deployment, either with ECR managed signing (`aws ecr put-signing-configuration` with an AWS Signer profile) or with cosign or Notation. Push the signature to the same repository, and redeploy from the signed digest.
  "
  tag severity:              "high"
  tag severity_source:       "assessed"
  tag nist:                  ['SI-7 a', 'SI-7 (6)']
  tag ksi:                   ['KSI-SVC-VRI']
  tag nist_r4:               ['SI-7', 'SI-7 (6)']
  tag cci:                   ['CCI-002704', 'CCI-002716']
  tag local_number:          "EF-1.5"
  tag srg:                   "SRG-APP-000131-CTR-000285"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  images = task_image_refs
  impact 0.7
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
    # read as a missing signature.
    determined = img.signing_determined?
    errors = img.lookup_errors
    describe "Signature lookup for #{ref[:repo]}@#{ref[:digest][0, 19]}" do
      it("can be determined") { expect(determined).to eq(true), "lookups failed: #{errors}" }
    end
    next unless determined

    describe img do
      it { should be_signed }
    end
  end
end
