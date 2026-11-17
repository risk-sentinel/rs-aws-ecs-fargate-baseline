# encoding: UTF-8

control "EF-11.3" do
  title "ALB HTTP listeners must redirect to HTTPS"
  desc "Any plaintext HTTP listener on an internet-facing ALB must redirect to "\
       "HTTPS (default action type=redirect, protocol HTTPS) so clients are "\
       "moved onto TLS rather than served over plaintext (SC-8 / FSBP ELB.1)."
  tag severity:              "medium"
  tag severity_source:       "unassessed"
  tag nist:                  ['SC-8', 'SC-8 (1)']
  tag ksi:                   ['KSI-CNA-MAT', 'KSI-CNA-ULN', 'KSI-SVC-SIN']
  tag nist_r4:               ['SC-8', 'SC-8 (1)']
  tag cci:                   ['CCI-002418', 'CCI-002421']
  tag local_number:          "EF-11.3"
  tag srg:                   "SRG-APP-000439-CTR-001070"
  tag fsbp:                  "ELB.1"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  albs = elbv2_internet_facing
  impact 0.5
  impact 0.0 if albs.empty?
  only_if("No internet-facing Application Load Balancers in scope") { !albs.empty? }

  albs.each do |lb|
    lst = aws_elasticloadbalancingv2_listeners(load_balancer_arn: lb[:arn])
    lst.protocols.zip(lst.default_actions, lst.ports).each do |proto, actions, port|
      next unless proto.to_s == "HTTP"
      redirects_https = Array(actions).any? do |a|
        type = a.respond_to?(:type) ? a.type : a[:type]
        rc   = a.respond_to?(:redirect_config) ? a.redirect_config : a[:redirect_config]
        proto2 = rc && (rc.respond_to?(:protocol) ? rc.protocol : rc[:protocol])
        type.to_s == "redirect" && proto2.to_s == "HTTPS"
      end
      describe "ALB #{lb[:name]} HTTP listener :#{port} redirects to HTTPS" do
        subject { redirects_https }
        it { should eq true }
      end
    end
  end
end
