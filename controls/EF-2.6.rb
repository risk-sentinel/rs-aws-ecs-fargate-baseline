# encoding: UTF-8

control "EF-2.6" do
  title "Containers must declare CPU and memory limits"
  desc "Per-container cpu and memory (or memoryReservation) bound resource use, "\
       "limiting the blast radius of a noisy/compromised container (SC-6)."
  tag severity:              "low"
  tag severity_source:       "assessed"
  tag nist:                  ["SC-6"]
  tag nist_r4:               ["SC-6"]
  tag cci:                   ["CCI-002392"]
  tag local_number:          "EF-2.6"
  tag srg:                   "SRG-APP-000435-CTR-001070"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  tds = fargate_task_definition_arns
  impact 0.3
  impact 0.0 if tds.empty?
  only_if("No Fargate task definitions in scope") { !tds.empty? }

  tds.each do |arn|
    td = aws_ecs_task_definition_full(task_definition: arn)
    describe "Containers missing cpu/memory limits in #{td.family}:#{td.revision}" do
      subject { td.containers_without_cpu_memory_limits }
      it { should be_empty }
    end
  end
end
