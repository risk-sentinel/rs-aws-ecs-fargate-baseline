# encoding: UTF-8

control "EF-2.1" do
  title "Containers must not run privileged"
  desc "A privileged container has near-host-level access, defeating container "\
       "isolation. No container definition may set privileged=true."
  desc  'check', "
    Examines the latest ACTIVE revision of every Fargate task definition in the scan regions (`scan_regions`). No container definition may set `privileged` to true.
  "
  desc  'fix', "
    Remove `privileged` from the container definition, or set it to false. Grant only the specific Linux capabilities the workload needs (see EF-2.4). Register a new task definition revision with the change (`aws ecs register-task-definition --cli-input-json file://taskdef.json`), then update the service to use it (`aws ecs update-service --cluster <cluster> --service <service> --task-definition <family>:<revision>`).
  "
  tag severity:              "high"
  tag severity_source:       "assessed"
  tag nist:                  ["AC-6"]
  tag ksi:                   ["KSI-IAM-ELP", "KSI-IAM-JIT"]
  tag nist_r4:               ["AC-6"]
  tag cci:                   ["CCI-000225"]
  tag local_number:          "EF-2.1"
  tag srg:                   "SRG-APP-000243-CTR-000595"
  tag fsbp:                  "ECS.4"
  tag cis_source:            "CIS AWS Compute v1.1.0 C-3.4"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  tds = fargate_task_definition_arns
  impact 0.7
  impact 0.0 if tds.empty?
  only_if("No Fargate task definitions in scope") { !tds.empty? }

  tds.each do |arn|
    td = aws_ecs_task_definition_full(task_definition: arn)
    describe "Privileged containers in #{td.family}:#{td.revision}" do
      subject { td.privileged_container_names }
      it { should be_empty }
    end
  end
end
