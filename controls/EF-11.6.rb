# encoding: UTF-8

control "EF-11.6" do
  title "ALBs must have deletion protection enabled"
  desc "deletion_protection.enabled must be true so the ingress LB cannot be "\
       "removed accidentally or maliciously, an availability safeguard "\
       "(CP-10 / FSBP ELB.6)."
  tag severity:              "low"
  tag severity_source:       "assessed"
  tag nist:                  ["CP-10"]
  tag nist_r4:               ["CP-10"]
  tag ksi:                   ["KSI-RPL-ABO", "KSI-RPL-ARP", "KSI-RPL-RRO", "KSI-RPL-TRC"]
  tag cci:                   ["CCI-004028"]
  tag local_number:          "EF-11.6"
  tag srg:                   "SRG-APP-000516-CTR-001325"
  tag fsbp:                  "ELB.6"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  albs = elbv2_internet_facing
  impact 0.3
  impact 0.0 if albs.empty?
  only_if("No internet-facing Application Load Balancers in scope") { !albs.empty? }

  albs.each do |lb|
    describe "ALB #{lb[:name]} deletion_protection" do
      subject { lb[:deletion_protection] }
      it { should eq true }
    end
  end
end
