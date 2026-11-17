# encoding: UTF-8

control "EF-4.4" do
  title "Task definitions must not embed long-lived AWS credentials"
  desc "Static AWS access keys must never be passed via environment variables; "\
       "use the task role for AWS access instead (IA-5/AC-6)."
  tag severity:              "high"
  tag severity_source:       "assessed"
  tag nist:                  ["SC-28", "AC-6"]
  tag ksi:                   ["KSI-IAM-ELP", "KSI-IAM-JIT", "KSI-SVC-SIN"]
  tag nist_r4:               ["AC-6", "SC-28"]
  tag cci:                   ["CCI-001199", "CCI-000225"]
  tag local_number:          "EF-4.4"
  tag fsbp:                  "ECS.8"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  aws_key_pattern = /\AAWS_(ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN)\z|ECS_ENGINE_AUTH_DATA/
  tds = fargate_task_definition_arns
  impact 0.7
  impact 0.0 if tds.empty?
  only_if("No Fargate task definitions in scope") { !tds.empty? }

  tds.each do |arn|
    td = aws_ecs_task_definition_full(task_definition: arn)
    offenders = []
    td.container_definitions.each do |c|
      Array(c[:environment]).each do |e|
        offenders << "#{c[:name]}:#{e[:name]}" if e[:name].to_s =~ aws_key_pattern
      end
    end
    describe "Embedded AWS credentials in #{td.family}:#{td.revision}" do
      subject { offenders }
      it { should be_empty }
    end
  end
end
