# encoding: UTF-8

control "EF-11.5" do
  title "ALBs must have access logging enabled"
  desc "access_logs.s3.enabled must be true so ingress request records are "\
       "captured for audit + incident response (AU-2 / FSBP ELB.5)."
  tag severity:              "medium"
  tag severity_source:       "unassessed"
  tag nist:                  ['AU-12 a', 'AU-12 c']
  tag ksi:                   ['KSI-MLA-LET']
  tag nist_r4:               ['AU-12 a', 'AU-12 c']
  tag cci:                   ['CCI-000169', 'CCI-000172']
  tag local_number:          "EF-11.5"
  tag srg:                   "SRG-APP-000092-CTR-000165"
  tag fsbp:                  "ELB.5"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  albs = elbv2_internet_facing
  impact 0.4
  impact 0.0 if albs.empty?
  only_if("No internet-facing Application Load Balancers in scope") { !albs.empty? }

  albs.each do |lb|
    describe "ALB #{lb[:name]} access_logs enabled" do
      subject { lb[:access_logs_enabled] }
      it { should eq true }
    end
  end
end
