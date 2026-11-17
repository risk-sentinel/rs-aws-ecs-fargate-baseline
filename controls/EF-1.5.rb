# encoding: UTF-8

control "EF-1.5" do
  title "Task images must be cryptographically signed"
  desc "Container images must carry a verifiable signature (e.g., cosign/notation) so "\
       "their provenance and integrity can be attested before deployment (CM-5(6)/SI-7). "\
       "Evaluated for digest-pinned task images; tag-only references are caught by EF-1.1."
  desc  'check', "
    For each in-scope Fargate task image referenced as an in-account ECR image by digest, call `ecr:DescribeImageSigningStatus` for that digest. The image must report at least one signing status. Images referenced by tag alone are skipped here and fail EF-1.1.
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

  images.each do |ref|
    next unless ref[:repo] && ref[:digest]
    describe aws_ecr_image(repository_name: ref[:repo], image_digest: ref[:digest]) do
      it { should be_signed }
    end
  end
end
