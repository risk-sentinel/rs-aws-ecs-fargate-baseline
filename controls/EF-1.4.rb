# encoding: UTF-8

control "EF-1.4" do
  title "ECR repositories must enforce image tag immutability"
  desc "Immutable tags prevent an existing tag from being overwritten with a "\
       "different image, preserving supply-chain integrity (CM-5(6)/SI-7)."
  desc  'check', "
    For every in-account ECR repository that an in-scope Fargate task definition pulls from, `imageTagMutability` must be `IMMUTABLE`.
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
  impact 0.5
  impact 0.0 if repos.empty?
  only_if("No in-account ECR repositories in scope") { !repos.empty? }

  repos.each do |repo|
    describe aws_ecr_repository(repository_name: repo) do
      its("image_tag_mutability") { should eq "IMMUTABLE" }
    end
  end
end
