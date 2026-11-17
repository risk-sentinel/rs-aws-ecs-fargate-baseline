# encoding: UTF-8

control "EF-8.1" do
  title "Every container must declare a log configuration"
  desc "logConfiguration must be set on each container so task output is captured "\
       "for audit."
  desc  'check', "
    Examines the latest ACTIVE revision of every Fargate task definition in the scan regions (`scan_regions`). Every container must define `logConfiguration` with a non-empty `logDriver`.
  "
  desc  'fix', "
    Add a log configuration to each container definition, for example:

    ```
    \"logConfiguration\": { \"logDriver\": \"awslogs\", \"options\": { \"awslogs-group\": \"<group>\", \"awslogs-region\": \"<region>\", \"awslogs-stream-prefix\": \"<prefix>\" } }
    ```

    Register a new task definition revision with the change (`aws ecs register-task-definition --cli-input-json file://taskdef.json`), then update the service to use it (`aws ecs update-service --cluster <cluster> --service <service> --task-definition <family>:<revision>`).
  "
  tag severity:              "medium"
  tag severity_source:       "unassessed"
  tag nist:                  ['AU-12 a', 'AU-12 c']
  tag ksi:                   ['KSI-MLA-LET']
  tag nist_r4:               ['AU-12 a', 'AU-12 c']
  tag cci:                   ['CCI-000169', 'CCI-000172']
  tag local_number:          "EF-8.1"
  tag srg:                   "SRG-APP-000510-CTR-001330"
  tag fsbp:                  "ECS.9"
  tag cis_source:            "CIS AWS Compute v1.1.0 C-3.7"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  tds = fargate_task_definition_arns
  impact 0.5
  impact 0.0 if tds.empty?
  only_if("No Fargate task definitions in scope") { !tds.empty? }

  tds.each do |arn|
    td = aws_ecs_task_definition_full(task_definition: arn)
    describe "Containers missing logging in #{td.family}:#{td.revision}" do
      subject { td.containers_missing_logging }
      it { should be_empty }
    end
  end
end
