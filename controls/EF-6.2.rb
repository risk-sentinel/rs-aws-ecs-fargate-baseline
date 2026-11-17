# encoding: UTF-8

control "EF-6.2" do
  title "Task definitions must not share the host PID namespace"
  desc "pidMode must not be 'host'; sharing the host PID namespace breaks process "\
       "isolation."
  desc  'check', "
    Examines the latest ACTIVE revision of every Fargate task definition in the scan regions (`scan_regions`). The task definition's `pidMode` must not be `host`.
  "
  desc  'fix', "
    Remove `pidMode` from the task definition, or set it to `task` where containers in the task need to share a process namespace. Register a new task definition revision with the change (`aws ecs register-task-definition --cli-input-json file://taskdef.json`), then update the service to use it (`aws ecs update-service --cluster <cluster> --service <service> --task-definition <family>:<revision>`).
  "
  tag severity:              "medium"
  tag severity_source:       "unassessed"
  tag nist:                  ['SC-39', 'CM-7 b']
  tag ksi:                   ['KSI-CMT-RMV', 'KSI-IAM-ELP', 'KSI-IAM-JIT', 'KSI-SVC-EIS']
  tag nist_r4:               ['CM-7 b', 'SC-39']
  tag cci:                   ['CCI-002530', 'CCI-000382']
  tag local_number:          "EF-6.2"
  tag srg:                   "SRG-APP-000431-CTR-001065"
  tag fsbp:                  "ECS.3"
  tag cis_source:            "CIS AWS Compute v1.1.0 C-3.3"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  tds = fargate_task_definition_arns
  impact 0.5
  impact 0.0 if tds.empty?
  only_if("No Fargate task definitions in scope") { !tds.empty? }

  tds.each do |arn|
    td = aws_ecs_task_definition_full(task_definition: arn)
    describe "pidMode for #{td.family}:#{td.revision}" do
      subject { td.pid_mode }
      it { should_not eq "host" }
    end
  end
end
