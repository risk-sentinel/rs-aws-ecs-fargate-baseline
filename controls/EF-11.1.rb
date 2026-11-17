# encoding: UTF-8

control "EF-11.1" do
  title "Internet-facing ALBs must offer a TLS (HTTPS) listener"
  desc "An internet-facing Application Load Balancer that terminates client "\
       "traffic must encrypt data in transit via an HTTPS/TLS listener "\
       "(SC-8). An HTTP-only internet-facing ALB exposes plaintext to the "\
       "internet."
  tag severity:              "high"
  tag severity_source:       "assessed"
  tag nist:                  ["SC-8", "SC-8 (1)"]
  tag ksi:                   ["KSI-CNA-MAT", "KSI-CNA-ULN", "KSI-SVC-SIN"]
  tag nist_r4:               ["SC-8", "SC-8 (1)"]
  tag cci:                   ["CCI-002418", "CCI-002421"]
  tag local_number:          "EF-11.1"
  tag srg:                   "SRG-APP-000439-CTR-001070"
  tag fsbp:                  "ELB.2"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  albs = elbv2_internet_facing
  impact 0.8
  impact 0.0 if albs.empty?
  only_if("No internet-facing Application Load Balancers in scope") { !albs.empty? }

  albs.each do |lb|
    protocols = aws_elasticloadbalancingv2_listeners(load_balancer_arn: lb[:arn]).protocols
    describe "Internet-facing ALB #{lb[:name]} — has an HTTPS/TLS listener" do
      subject { protocols.any? { |p| %w(HTTPS TLS).include?(p.to_s) } }
      it { should eq true }
    end
  end
end
