# encoding: UTF-8

control "EF-6.3" do
  title "Fargate services must run the latest platform version"
  desc "platform_version should be LATEST so security patches apply "\
       "automatically (SI-2). A pinned numeric version drifts behind."
  tag severity:              "medium"
  tag severity_source:       "unassessed"
  tag nist:                  ["SI-2 a"]
  tag ksi:                   ["KSI-CMT-VTD"]
  tag nist_r4:               ["SI-2 a"]
  tag cci:                   ["CCI-001225"]
  tag local_number:          "EF-6.3"
  tag srg:                   "SRG-APP-000456-CTR-001125"
  tag fsbp:                  "ECS.10"
  tag cis_source:            "CIS AWS Compute v1.1.0 C-3.8"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  keys = ecs_service_keys
  impact 0.5
  impact 0.0 if keys.empty?
  only_if("No ECS services in scope") { !keys.empty? }

  keys.each do |k|
    svc = aws_ecs_service_full(cluster: k[:cluster], service: k[:service])
    next unless svc.fargate?

    describe "Platform version for service #{svc.service_name}" do
      subject { svc.platform_version }
      it { should eq "LATEST" }
    end
  end
end
