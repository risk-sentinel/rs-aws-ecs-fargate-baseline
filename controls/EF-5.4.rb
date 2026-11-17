# encoding: UTF-8

control "EF-5.4" do
  title "Service tasks must run in private subnets"
  desc "Each subnet a Fargate service launches into must be private (no default "\
       "route to an internet gateway), keeping tasks off the public internet. Deep "\
       "check resolves the subnet route tables."
  desc  'check', "
    For every Fargate ECS service in the scan regions, resolve the route table of each subnet the service launches into. No subnet may have a default route (`0.0.0.0/0` or `::/0`) to an internet gateway (`igw-`).
  "
  desc  'fix', "
    Move the service to private subnets, whose default route goes to a NAT gateway or has none:

    ```
    aws ecs update-service --cluster <cluster> --service <service> --network-configuration 'awsvpcConfiguration={subnets=[<private-subnet>,...],securityGroups=[<sg>],assignPublicIp=DISABLED}'
    ```

    Put internet-facing entry points (load balancers) in public subnets instead.
  "
  tag severity:              "high"
  tag severity_source:       "assessed"
  tag nist:                  ["SC-7 a"]
  tag ksi:                   ["KSI-CNA-ULN", "KSI-SVC-EIS"]
  tag nist_r4:               ["SC-7 a"]
  tag cci:                   ["CCI-001097"]
  tag local_number:          "EF-5.4"
  tag srg:                   "SRG-APP-000039-CTR-000110"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  keys = ecs_service_keys
  impact 0.7
  impact 0.0 if keys.empty?
  only_if("No ECS services in scope") { !keys.empty? }

  keys.each do |k|
    svc = aws_ecs_service_full(cluster: k[:cluster], service: k[:service])
    next unless svc.fargate?

    svc.subnets.each do |subnet_id|
      # Resolved at CONTROL scope, once per subnet, and closed over. A helper
      # mixed into Inspec::Rule is not in scope inside describe/subject, so
      # calling it there raises NameError at exec -- and resolving it twice
      # (subject and expectation) would also search the regions twice.
      routing = subnet_routing(subnet_id)
      has_igw_route = routing.internet_gateway_route?
      describe "Subnet #{subnet_id} (service #{svc.service_name}) routing" do
        subject { routing }
        it "must not have a default route to an internet gateway" do
          expect(has_igw_route).to eq(false)
        end
      end
    end
  end
end
