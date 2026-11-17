# encoding: UTF-8

control "EF-2.8" do
  title "Containers must define a health check"
  desc "A healthCheck lets ECS detect and replace unhealthy tasks, supporting "\
       "availability."
  desc  'check', "
    Examines the latest ACTIVE revision of every Fargate task definition in the scan regions (`scan_regions`). Every container must define a `healthCheck` with a non-empty `command`.
  "
  desc  'fix', "
    Add a health check to each container definition, for example:

    ```
    \"healthCheck\": { \"command\": [\"CMD-SHELL\", \"curl -f http://localhost:8080/health || exit 1\"], \"interval\": 30, \"timeout\": 5, \"retries\": 3 }
    ```

    Register a new task definition revision with the change (`aws ecs register-task-definition --cli-input-json file://taskdef.json`), then update the service to use it (`aws ecs update-service --cluster <cluster> --service <service> --task-definition <family>:<revision>`).
  "
  tag severity:              "low"
  tag severity_source:       "assessed"
  tag nist:                  ['SI-13 b', 'SI-13 (4) (a)']
  tag nist_r4:               ['SI-13 (4) (a)', 'SI-13 b']
  tag cci:                   ['CCI-001318', 'CCI-001326']
  tag local_number:          "EF-2.8"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  tds = fargate_task_definition_arns
  impact 0.3
  impact 0.0 if tds.empty?
  only_if("No Fargate task definitions in scope") { !tds.empty? }

  tds.each do |arn|
    td = aws_ecs_task_definition_full(task_definition: arn)
    describe "Containers without health checks in #{td.family}:#{td.revision}" do
      subject { td.containers_without_healthcheck }
      it { should be_empty }
    end
  end
end
