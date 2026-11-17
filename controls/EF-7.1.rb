# encoding: UTF-8

control "EF-7.1" do
  title "ECS Exec must be disabled except on explicitly allowed services"
  desc "enableExecuteCommand opens an interactive shell into running tasks "\
       "(AC-17/AC-6(9)). It must be false unless the service is listed in "\
       "ecs_exec_allowed_services."
  tag severity:              "high"
  tag severity_source:       "assessed"
  tag nist:                  ['AC-17 b', 'CM-7 b']
  tag ksi:                   ['KSI-CMT-RMV', 'KSI-IAM-ELP', 'KSI-IAM-JIT']
  tag nist_r4:               ['AC-17 b', 'CM-7 b']
  tag cci:                   ['CCI-000065', 'CCI-000382']
  tag local_number:          "EF-7.1"
  tag srg:                   "SRG-APP-000033-CTR-000095"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  allowed = input("ecs_exec_allowed_services")
  keys = ecs_service_keys
  impact 0.7
  impact 0.0 if keys.empty?
  only_if("No ECS services in scope") { !keys.empty? }

  keys.each do |k|
    svc = aws_ecs_service_full(cluster: k[:cluster], service: k[:service])
    permitted = allowed.include?(svc.service_name) || allowed.include?(svc.service_arn)
    next if permitted # allowed services are governed by EF-7.2 instead

    describe "ECS Exec for service #{svc.service_name}" do
      subject { svc.exec_enabled? }
      it { should eq false }
    end
  end
end
