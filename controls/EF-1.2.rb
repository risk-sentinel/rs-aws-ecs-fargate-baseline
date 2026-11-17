# encoding: UTF-8

control "EF-1.2" do
  title "Container images must come from trusted registries"
  desc "Only images from approved registries (private ECR or vetted sources) "\
       "may be deployed. Fails closed when trusted_image_registries is empty."
  desc  'check', "
    Examines the latest ACTIVE revision of every Fargate task definition in the scan regions (`scan_regions`). Every container's `image` must start with one of the prefixes in the input `trusted_image_registries`. When that input is empty, every container fails: there is no approved registry to match.
  "
  desc  'fix', "
    Set `trusted_image_registries` to the approved registry prefixes (for example `<account>.dkr.ecr.<region>.amazonaws.com/`). Move any image from an unapproved registry into an approved one, for example by pulling, re-tagging and pushing it to a private ECR repository, and point the container's `image` at it. Register a new task definition revision with the change (`aws ecs register-task-definition --cli-input-json file://taskdef.json`), then update the service to use it (`aws ecs update-service --cluster <cluster> --service <service> --task-definition <family>:<revision>`).
  "
  tag severity:              "high"
  tag severity_source:       "assessed"
  tag nist:                  ['CM-7 (5) (b)', 'CM-7 a']
  tag ksi:                   ['KSI-CMT-RMV', 'KSI-IAM-JIT', 'KSI-PIY-GIV']
  tag nist_r4:               ['CM-7 (5) (b)', 'CM-7 a']
  tag cci:                   ['CCI-001774', 'CCI-000381']
  tag local_number:          "EF-1.2"
  tag srg:                   "SRG-APP-000141-CTR-000320"
  tag fsbp:                  "n/a"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  trusted = input("trusted_image_registries")
  tds = fargate_task_definition_arns
  impact 0.7
  impact 0.0 if tds.empty?
  only_if("No Fargate task definitions in scope") { !tds.empty? }

  tds.each do |arn|
    td = aws_ecs_task_definition_full(task_definition: arn)
    describe "Untrusted images in #{td.family}:#{td.revision}" do
      subject { td.untrusted_image_containers(trusted) }
      it { should be_empty }
    end
  end
end
