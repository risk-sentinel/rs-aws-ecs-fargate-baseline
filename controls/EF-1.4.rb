# encoding: UTF-8

control "EF-1.4" do
  title "ECR repositories must enforce image tag immutability"
  desc "Immutable tags prevent an existing tag from being overwritten with a "\
       "different image, preserving supply-chain integrity."
  desc  'check', "
    For every ECR repository an in-scope Fargate task definition pulls from, queried in the region and registry (account) named in the image URI, `imageTagMutability` must be `IMMUTABLE`. Images from any other registry are reported as skipped, not assessed.
  "
  desc  'fix', "
    ```
    aws ecr put-image-tag-mutability --repository-name <repo> --image-tag-mutability IMMUTABLE
    ```

    Build pipelines must then push a new tag for every build rather than overwrite an existing one.
  "
  tag severity:              "medium"
  tag severity_source:       "unassessed"
  tag nist:                  ['CM-5 (6)']
  tag nist_r4:               ['CM-5 (6)']
  tag cci:                   ['CCI-001499']
  tag local_number:          "EF-1.4"
  tag srg:                   "SRG-APP-000131-CTR-000285"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  repos = ecr_repos_in_scope
  other = unassessable_images(need_digest: false)
  impact 0.5
  impact 0.0 if repos.empty?
  only_if("No ECR repositories back the in-scope task images (#{other.size} image(s) from other registries)") { !repos.empty? }

  other.each do |raw, why|
    describe "Image #{raw}" do
      skip "Not assessed: #{why}."
    end
  end

  repos.each do |r|
    describe aws_ecr_repository(repository_name: r[:repo], region: r[:region], registry_id: r[:registry_id]) do
      its("image_tag_mutability") { should eq "IMMUTABLE" }
    end
  end
end
