# encoding: UTF-8

control "EF-11.2" do
  title "ALB HTTPS listeners must use a strong TLS security policy"
  desc "Each HTTPS/TLS listener must use a predefined SSL policy that enforces "\
       "TLS 1.2 or higher (SC-13). Legacy policies (TLS 1.0/1.1, the 2015/2016 "\
       "sets) permit deprecated protocols. The approved set is the "\
       "`alb_strong_ssl_policies` input."
  desc  'check', "
    For every internet-facing Application Load Balancer in the scan regions, every `HTTPS` or `TLS` listener's SSL policy must be one of the input `alb_strong_ssl_policies`.
  "
  desc  'fix', "
    ```
    aws elbv2 modify-listener --listener-arn <listener-arn> --ssl-policy <policy from alb_strong_ssl_policies>
    ```

    For example `ELBSecurityPolicy-TLS13-1-2-2021-06`, which allows only TLS 1.2 and 1.3.
  "
  tag severity:              "high"
  tag severity_source:       "assessed"
  tag nist:                  ['SC-13 b', 'SC-8 (1)']
  tag ksi:                   ['KSI-SVC-SIN', 'KSI-SVC-VRI']
  tag nist_r4:               ['SC-13', 'SC-8 (1)']
  tag cci:                   ['CCI-002450', 'CCI-002421']
  tag local_number:          "EF-11.2"
  tag srg:                   "SRG-APP-000439-CTR-001070"
  tag fsbp:                  "ELB.17"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  albs     = elbv2_internet_facing
  approved = input("alb_strong_ssl_policies")
  impact 0.8
  impact 0.0 if albs.empty?
  only_if("No internet-facing Application Load Balancers in scope") { !albs.empty? }

  albs.each do |lb|
    lst = aws_elasticloadbalancingv2_listeners(load_balancer_arn: lb[:arn])
    lst.protocols.zip(lst.ssl_policies, lst.ports).each do |proto, policy, port|
      next unless %w(HTTPS TLS).include?(proto.to_s)
      describe "ALB #{lb[:name]} HTTPS listener :#{port} SSL policy" do
        subject { policy }
        it { should be_in approved }
      end
    end
  end
end
