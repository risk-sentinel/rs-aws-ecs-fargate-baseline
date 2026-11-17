# encoding: UTF-8

control "EF-11.4" do
  title "ALBs must drop invalid HTTP header fields"
  desc "routing.http.drop_invalid_header_fields.enabled must be true so the ALB "\
       "strips malformed headers before forwarding to the Fargate tasks "\
       "(request-smuggling / header-injection hardening — FSBP ELB.4 / SI-10)."
  tag severity:              "medium"
  tag severity_source:       "unassessed"
  tag nist:                  ["SI-10"]
  tag ksi:                   ["KSI-CNA-MAT", "KSI-PIY-RSD"]
  tag nist_r4:               ["SI-10"]
  tag cci:                   ["CCI-001310"]
  tag local_number:          "EF-11.4"
  tag srg:                   "SRG-APP-000251-CTR-000600"
  tag fsbp:                  "ELB.4"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  albs = elbv2_internet_facing
  impact 0.4
  impact 0.0 if albs.empty?
  only_if("No internet-facing Application Load Balancers in scope") { !albs.empty? }

  albs.each do |lb|
    describe "ALB #{lb[:name]} drop_invalid_header_fields" do
      subject { lb[:drop_invalid_headers] }
      it { should eq true }
    end
  end
end
