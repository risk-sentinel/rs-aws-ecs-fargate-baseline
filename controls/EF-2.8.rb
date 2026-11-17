# encoding: UTF-8

control "EF-2.8" do
  title "Containers must define a health check"
  desc "A healthCheck lets ECS detect and replace unhealthy tasks, supporting "\
       "availability (SI-13/CP-10)."
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
