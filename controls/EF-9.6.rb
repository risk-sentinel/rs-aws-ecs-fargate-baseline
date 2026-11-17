# encoding: UTF-8

control "EF-9.6" do
  title "FIPS-validated cryptographic modules (AWS-provided)"
  desc  "The cryptographic modules underpinning Fargate / AWS service endpoints are "\
        "FIPS-validated by AWS and inherited (SRG-CTR crypto domain)."
  tag severity: "medium"
  tag severity_source: "unassessed"
  tag nist: ['SC-13 b', 'IA-7']
  tag ksi:  ['KSI-IAM-JIT', 'KSI-SVC-SIN', 'KSI-SVC-VRI']
  tag nist_r4: ['IA-7', 'SC-13']
  tag cci:  ['CCI-002450', 'CCI-000803']
  tag local_number: "EF-9.6"
  tag srg_source: "DISA Container Platform SRG V2R4 (crypto domain, AWS-inherited)"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "inherited"
  tag inherited_from: "aws-shared-responsibility"
  tag attestation_references: ["AWS FedRAMP High", "AWS DoD SRG IL4/IL5", "AWS SOC 2 Type II"]
  tag exec_validated: false
  impact 0.5

  uri = input("inherited_evidence_uri", value: "")
  uri = attestation_uri(:leveraged, "aws-fargate-fedramp", ext: "json") if uri.to_s.empty?
  max_age_days = input("leveraged_evidence_max_age_days", value: 365)

  if uri.to_s.empty?
    describe "EF-9.6 AWS-inherited FIPS-crypto evidence (no leveraged source configured)" do
      skip "inherited-from-aws: FIPS-validated crypto modules are AWS-provided. Set leveraged_evidence_base / inherited_evidence_uri, or `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "EF-9.6 AWS authorization evidence (#{uri})" do
      it("is reachable") { expect(doc.connection_error).to be_nil, "evidence unreachable: #{doc.connection_error}" }
      it("exists") { expect(doc.exists?).to eq(true) }
      it("is current within #{max_age_days} days") { expect(doc.current?).to eq(true) }
    end
  end
end
