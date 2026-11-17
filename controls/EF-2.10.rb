# encoding: UTF-8

control "EF-2.10" do
  title "Containers must not bind privileged ports (<1024)"
  desc "Container ports below 1024 require elevated privilege historically and "\
       "are disallowed by SRG-CTR; bind unprivileged ports instead (CM-7)."
  desc  'check', "
    Examines the latest ACTIVE revision of every Fargate task definition in the scan regions (`scan_regions`). No container may map a `containerPort` between 1 and 1023.
  "
  desc  'fix', "
    Configure the application to listen on a port of 1024 or higher, and update `portMappings` and any load balancer target group to match. Register a new task definition revision with the change (`aws ecs register-task-definition --cli-input-json file://taskdef.json`), then update the service to use it (`aws ecs update-service --cluster <cluster> --service <service> --task-definition <family>:<revision>`).
  "
  tag severity:              "low"
  tag severity_source:       "assessed"
  tag nist:                  ['CM-7 b']
  tag ksi:                   ['KSI-CMT-RMV', 'KSI-IAM-JIT']
  tag nist_r4:               ['CM-7 b']
  tag cci:                   ['CCI-000382']
  tag local_number:          "EF-2.10"
  tag srg:                   "SRG-APP-000142-CTR-000330"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  tds = fargate_task_definition_arns
  impact 0.3
  impact 0.0 if tds.empty?
  only_if("No Fargate task definitions in scope") { !tds.empty? }

  tds.each do |arn|
    td = aws_ecs_task_definition_full(task_definition: arn)
    describe "Containers binding privileged ports in #{td.family}:#{td.revision}" do
      subject { td.containers_with_privileged_ports }
      it { should be_empty }
    end
  end
end
