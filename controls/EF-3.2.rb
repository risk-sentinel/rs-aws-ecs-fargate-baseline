# encoding: UTF-8

control "EF-3.2" do
  title "Injected secrets must reference Secrets Manager / SSM ARNs"
  desc "Every secrets[].valueFrom must be an ARN (Secrets Manager or SSM Parameter "\
       "Store), not an inline/plaintext value."
  desc  'check', "
    Examines the latest ACTIVE revision of every Fargate task definition in the scan regions (`scan_regions`). Every entry in each container's `secrets` must have a `valueFrom` that is an ARN, for a Secrets Manager secret or an SSM parameter.
  "
  desc  'fix', "
    Replace each non-ARN `valueFrom` with the full ARN of the Secrets Manager secret or SSM parameter. Register a new task definition revision with the change (`aws ecs register-task-definition --cli-input-json file://taskdef.json`), then update the service to use it (`aws ecs update-service --cluster <cluster> --service <service> --task-definition <family>:<revision>`).
  "
  tag severity:              "high"
  tag severity_source:       "assessed"
  tag nist:                  ["IA-5 (7)", "SC-28"]
  tag ksi:                   ["KSI-SVC-SIN"]
  tag nist_r4:               ["SC-28"]
  tag cci:                   ["CCI-001199", "CCI-004069"]
  tag local_number:          "EF-3.2"
  tag srg:                   "SRG-APP-000038-CTR-000105"
  tag nist_800_190:          "3.4"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  tds = fargate_task_definition_arns
  impact 0.7
  impact 0.0 if tds.empty?
  only_if("No Fargate task definitions in scope") { !tds.empty? }

  tds.each do |arn|
    td = aws_ecs_task_definition_full(task_definition: arn)
    describe "Non-ARN secret references in #{td.family}:#{td.revision}" do
      subject { td.containers_with_non_arn_secrets }
      it { should be_empty }
    end
  end
end
