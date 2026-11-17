# encoding: UTF-8

control "EF-2.5" do
  title "Containers must not request privilege-escalating capabilities"
  desc "Containers must not add SYS_ADMIN/SYS_PTRACE/ALL, which enable "\
       "privilege escalation and host introspection (AC-6)."
  desc  'check', "
    Examines the latest ACTIVE revision of every Fargate task definition in the scan regions (`scan_regions`). No container may add `SYS_ADMIN`, `SYS_PTRACE` or `ALL` in `linuxParameters.capabilities.add`.
  "
  desc  'fix', "
    Remove `SYS_ADMIN`, `SYS_PTRACE` and `ALL` from `linuxParameters.capabilities.add`. On Fargate, `SYS_PTRACE` is the only capability that can be added; add it only where a debugging or monitoring sidecar requires it. Register a new task definition revision with the change (`aws ecs register-task-definition --cli-input-json file://taskdef.json`), then update the service to use it (`aws ecs update-service --cluster <cluster> --service <service> --task-definition <family>:<revision>`).
  "
  tag severity:              "high"
  tag severity_source:       "assessed"
  tag nist:                  ['AC-6', 'AC-6 (8)']
  tag ksi:                   ['KSI-IAM-ELP', 'KSI-IAM-JIT']
  tag nist_r4:               ['AC-6', 'AC-6 (8)']
  tag cci:                   ['CCI-000225', 'CCI-002233']
  tag local_number:          "EF-2.5"
  tag srg:                   "SRG-APP-000342-CTR-000775"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  tds = fargate_task_definition_arns
  impact 0.7
  impact 0.0 if tds.empty?
  only_if("No Fargate task definitions in scope") { !tds.empty? }

  tds.each do |arn|
    td = aws_ecs_task_definition_full(task_definition: arn)
    describe "Privilege-escalating containers in #{td.family}:#{td.revision}" do
      subject { td.containers_with_no_new_privileges_disabled }
      it { should be_empty }
    end
  end
end
