# encoding: UTF-8

control "EF-2.2" do
  title "Containers must run as a non-root user"
  desc "Each container definition must set a non-root user. Running as root "\
       "(or leaving user unset) increases container-escape blast radius."
  desc  'check', "
    Examines the latest ACTIVE revision of every Fargate task definition in the scan regions (`scan_regions`). Every container must set `user` to a non-root user. A container fails when `user` is unset, `root`, `0`, or starts with `root:` or `0:`.
  "
  desc  'fix', "
    Set `user` in the container definition to a non-root UID or name, for example `\"user\": \"1000:1000\"`, and make sure the image runs correctly as that user (file ownership, ports above 1024). Register a new task definition revision with the change (`aws ecs register-task-definition --cli-input-json file://taskdef.json`), then update the service to use it (`aws ecs update-service --cluster <cluster> --service <service> --task-definition <family>:<revision>`).
  "
  tag severity:              "medium"
  tag severity_source:       "unassessed"
  tag nist:                  ["AC-6"]
  tag ksi:                   ["KSI-IAM-ELP", "KSI-IAM-JIT"]
  tag nist_r4:               ["AC-6"]
  tag cci:                   ["CCI-000225"]
  tag local_number:          "EF-2.2"
  tag srg:                   "SRG-APP-000133-CTR-000290"
  tag fsbp:                  "ECS.20"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  tds = fargate_task_definition_arns
  impact 0.5
  impact 0.0 if tds.empty?
  only_if("No Fargate task definitions in scope") { !tds.empty? }

  tds.each do |arn|
    td = aws_ecs_task_definition_full(task_definition: arn)
    describe "Root-user containers in #{td.family}:#{td.revision}" do
      subject { td.root_user_container_names }
      it { should be_empty }
    end
  end
end
