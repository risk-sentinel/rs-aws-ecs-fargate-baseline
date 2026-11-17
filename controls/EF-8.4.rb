# encoding: UTF-8

control "EF-8.4" do
  title "Services, clusters, and task definitions must carry required tags"
  desc "Required governance tags (required_tag_keys) must be present for "\
       "inventory and ABAC (CM-8). Empty input = require at least one tag."
  tag severity:              "low"
  tag severity_source:       "assessed"
  tag nist:                  ["CM-8 a 1"]
  tag ksi:                   ["KSI-PIY-GIV"]
  tag nist_r4:               ["CM-8"]
  tag cci:                   ["CCI-003962"]
  tag local_number:          "EF-8.4"
  tag fsbp:                  "ECS.13/14/15"
  tag cis_source:            "CIS AWS Compute v1.1.0 C-3.10/3.11/3.12"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  required = input("required_tag_keys")
  keys = ecs_service_keys
  clusters = ecs_cluster_arns
  tds = fargate_task_definition_arns
  applicable = !(keys.empty? && clusters.empty? && tds.empty?)
  impact 0.3
  impact 0.0 unless applicable
  only_if("No ECS resources in scope") { applicable }

  check = lambda do |label, present_keys|
    describe "Tags for #{label}" do
      subject { present_keys }
      if required.empty?
        it("must have at least one tag") { expect(present_keys).not_to be_empty }
      else
        it("must include #{required.join(', ')}") { expect(present_keys).to include(*required) }
      end
    end
  end

  clusters.each { |c| check.call("cluster #{c.split('/').last}", aws_ecs_cluster_full(cluster: c).tag_keys) }
  keys.each do |k|
    svc = aws_ecs_service_full(cluster: k[:cluster], service: k[:service])
    check.call("service #{svc.service_name}", svc.tag_keys)
  end
  tds.each do |a|
    td = aws_ecs_task_definition_full(task_definition: a)
    check.call("task def #{td.family}:#{td.revision}", td.tag_keys)
  end
end
