# encoding: UTF-8

control "EF-1.3" do
  title "ECR repositories backing task images must have scan-on-push enabled"
  desc "Image vulnerability scanning must run automatically on push so newly "\
       "introduced CVEs are detected."
  desc  'check', "
    For every ECR repository an in-scope Fargate task definition pulls from, queried in the region and registry (account) named in the image URI, the repository must have an image scanning configuration with `scanOnPush` true. Images from any other registry are reported as skipped, not assessed.
  "
  desc  'fix', "
    ```
    aws ecr put-image-scanning-configuration --repository-name <repo> --image-scanning-configuration scanOnPush=true
    ```

    Alternatively, enable a registry-level scanning rule (`aws ecr put-registry-scanning-configuration`) covering the repository.
  "
  tag severity:              "medium"
  tag severity_source:       "unassessed"
  tag nist:                  ["RA-5 a"]
  tag ksi:                   ["KSI-SCR-MON"]
  tag nist_r4:               ["RA-5 a"]
  tag cci:                   ["CCI-001054"]
  tag local_number:          "EF-1.3"
  tag srg:                   "SRG-APP-000456-CTR-001125"
  tag fsbp:                  "ECR.1"
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
      its("image_scanning_configuration") { should_not be_nil }
      its("scan_on_push") { should eq true }
    end
  end
end
