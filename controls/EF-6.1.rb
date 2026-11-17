# encoding: UTF-8

control "EF-6.1" do
  title "Host-network task definitions must not allow privileged/root containers"
  desc "If a task definition uses host network mode, no container may be "\
       "privileged or run as root (defense in depth; Fargate forbids host "\
       "mode but the assertion keeps the profile portable)."
  tag severity:              "high"
  tag severity_source:       "assessed"
  tag nist:                  ["AC-6"]
  tag ksi:                   ["KSI-IAM-ELP", "KSI-IAM-JIT"]
  tag nist_r4:               ["AC-6"]
  tag cci:                   ["CCI-000225"]
  tag local_number:          "EF-6.1"
  tag srg:                   "SRG-APP-000243-CTR-000595"
  tag cis_source:            "CIS AWS Compute v1.1.0 C-3.1"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  tds = fargate_task_definition_arns.select { |a| aws_ecs_task_definition_full(task_definition: a).host_network? }
  impact 0.7
  impact 0.0 if tds.empty?
  only_if("No host-network task definitions in scope") { !tds.empty? }

  tds.each do |arn|
    td = aws_ecs_task_definition_full(task_definition: arn)
    describe "Host-network privileged/root containers in #{td.family}:#{td.revision}" do
      subject { (td.privileged_container_names + td.root_user_container_names).uniq }
      it { should be_empty }
    end
  end
end
