# encoding: UTF-8

control "EF-9.1" do
  title "Fargate host OS / kernel hardening (AWS-managed)"
  desc  "The Fargate microVM host OS, kernel hardening, and patching are AWS-managed "\
        "and inherited via AWS's FedRAMP/DoD authorization. The consumer cannot "\
        "configure or query the host; evidence is the AWS authorization package."
  tag severity: "medium"
  tag severity_source: "unassessed"
  tag nist: ["CM-6 b", "SI-2 c"]
  tag ksi:  ["KSI-CMT-LMC", "KSI-CMT-RMV", "KSI-CMT-VTD", "KSI-MLA-EVC", "KSI-SVC-ACM"]
  tag nist_r4: ["CM-6 b", "SI-2 c"]
  tag cci: ["CCI-000366", "CCI-002605"]
  tag local_number: "EF-9.1"
  tag srg_source: "DISA Container Platform SRG V2R4 (host/runtime domain, AWS-inherited)"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "inherited"
  tag inherited_from: "aws-shared-responsibility"
  tag attestation_references: ["AWS FedRAMP High", "AWS FedRAMP Moderate", "AWS DoD SRG IL4/IL5", "AWS SOC 2 Type II"]
  tag exec_validated: false
  impact 0.5

  uri = input("inherited_evidence_uri", value: "")
  uri = attestation_uri(:leveraged, "aws-fargate-fedramp", ext: "json") if uri.to_s.empty?
  max_age_days = input("leveraged_evidence_max_age_days", value: 365)

  if uri.to_s.empty?
    describe "EF-9.1 AWS-inherited host-OS evidence (no leveraged source configured)" do
      skip "inherited-from-aws: Fargate host OS/kernel is AWS-managed. Set leveraged_evidence_base / inherited_evidence_uri to AWS's pulled FedRAMP/DoD authorization manifest, or supply a CMS-pattern attestation via `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "EF-9.1 AWS authorization evidence (#{uri})" do
      it("is reachable") { expect(doc.connection_error).to be_nil, "evidence unreachable: #{doc.connection_error}" }
      it("exists") { expect(doc.exists?).to eq(true) }
      it("is current within #{max_age_days} days") { expect(doc.current?).to eq(true) }
    end
  end
end
