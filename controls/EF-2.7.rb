# encoding: UTF-8

control "EF-2.7" do
  title "Containers should set ulimits"
  desc "ulimits (e.g. nofile) bound per-process resource consumption."
  desc  'check', "
    Examines the latest ACTIVE revision of every Fargate task definition in the scan regions (`scan_regions`). Every container must declare at least one entry in `ulimits`.
  "
  desc  'fix', "
    Add `ulimits` to each container definition, for example:

    ```
    \"ulimits\": [ { \"name\": \"nofile\", \"softLimit\": 1024, \"hardLimit\": 4096 } ]
    ```

    Register a new task definition revision with the change (`aws ecs register-task-definition --cli-input-json file://taskdef.json`), then update the service to use it (`aws ecs update-service --cluster <cluster> --service <service> --task-definition <family>:<revision>`).
  "
  tag severity:              "low"
  tag severity_source:       "assessed"
  tag nist:                  ["SC-6"]
  tag nist_r4:               ["SC-6"]
  tag cci:                   ["CCI-002392"]
  tag local_number:          "EF-2.7"
  tag srg:                   "SRG-APP-000435-CTR-001070"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  tds = fargate_task_definition_arns
  impact 0.3
  impact 0.0 if tds.empty?
  only_if("No Fargate task definitions in scope") { !tds.empty? }

  tds.each do |arn|
    td = aws_ecs_task_definition_full(task_definition: arn)
    describe "Containers without ulimits in #{td.family}:#{td.revision}" do
      subject { td.containers_without_ulimits }
      it { should be_empty }
    end
  end
end
