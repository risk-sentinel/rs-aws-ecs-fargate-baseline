# encoding: UTF-8

control "EF-5.2" do
  title "Services must not auto-assign public IPs"
  desc "assignPublicIp must be DISABLED so tasks are not directly reachable "\
       "from the internet (SC-7)."
  desc  'check', "
    For every Fargate ECS service in the scan regions, `networkConfiguration.awsvpcConfiguration.assignPublicIp` must be `DISABLED`.
  "
  desc  'fix', "
    ```
    aws ecs update-service --cluster <cluster> --service <service> --network-configuration 'awsvpcConfiguration={subnets=[<private-subnet>,...],securityGroups=[<sg>],assignPublicIp=DISABLED}'
    ```

    Tasks then need a NAT gateway or VPC endpoints for outbound AWS access.
  "
  tag severity:              "high"
  tag severity_source:       "assessed"
  tag nist:                  ['SC-7 c', 'SC-7 a']
  tag ksi:                   ['KSI-CNA-ULN', 'KSI-SVC-EIS']
  tag nist_r4:               ['SC-7 a', 'SC-7 c']
  tag cci:                   ['CCI-001098', 'CCI-001097']
  tag local_number:          "EF-5.2"
  tag srg:                   "SRG-APP-000039-CTR-000110"
  tag fsbp:                  "ECS.2"
  tag cis_source:            "CIS AWS Compute v1.1.0 C-3.2"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  keys = ecs_service_keys
  impact 0.7
  impact 0.0 if keys.empty?
  only_if("No ECS services in scope") { !keys.empty? }

  keys.each do |k|
    svc = aws_ecs_service_full(cluster: k[:cluster], service: k[:service])
    next unless svc.fargate?

    describe "assignPublicIp for service #{svc.service_name}" do
      subject { svc.assign_public_ip }
      it { should eq "DISABLED" }
    end
  end
end
