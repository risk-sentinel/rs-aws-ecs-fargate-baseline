# encoding: UTF-8

control "EF-5.5" do
  title "Service security groups must not allow 0.0.0.0/0 ingress"
  desc "The security groups attached to a Fargate service must not permit "\
       "unrestricted inbound access from the internet (SC-7(3)). Deep check "\
       "resolves each SG's ingress rules."
  desc  'check', "
    For every Fargate ECS service in the scan regions, no security group attached to the service may allow inbound traffic from `0.0.0.0/0`.
  "
  desc  'fix', "
    Remove the open rule and allow inbound only from the load balancer's security group or specific CIDRs:

    ```
    aws ec2 revoke-security-group-ingress --group-id <sg> --ip-permissions '<the 0.0.0.0/0 rule>'
    aws ec2 authorize-security-group-ingress --group-id <sg> --protocol tcp --port <port> --source-group <alb-sg>
    ```
  "
  tag severity:              "high"
  tag severity_source:       "assessed"
  tag nist:                  ["SC-7 a"]
  tag ksi:                   ["KSI-CNA-ULN", "KSI-SVC-EIS"]
  tag nist_r4:               ["SC-7 a"]
  tag cci:                   ["CCI-001097"]
  tag local_number:          "EF-5.5"
  tag srg:                   "SRG-APP-000142-CTR-000325"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  keys = ecs_service_keys
  impact 0.7
  impact 0.0 if keys.empty?
  only_if("No ECS services in scope") { !keys.empty? }

  keys.each do |k|
    svc = aws_ecs_service_full(cluster: k[:cluster], service: k[:service])
    next unless svc.fargate?

    svc.security_groups.each do |sg_id|
      describe "Security group #{sg_id} (service #{svc.service_name})" do
        subject { aws_security_group(group_id: sg_id) }
        it { should_not allow_in(ipv4_range: "0.0.0.0/0") }
      end
    end
  end
end
