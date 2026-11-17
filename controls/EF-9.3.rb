# encoding: UTF-8

control "EF-9.3" do
  title "ECS / Fargate orchestrator control plane (AWS-managed)"
  desc  "The ECS control plane (scheduling, API, state) is AWS-managed and inherited "\
        "via AWS authorization (SRG-CTR orchestrator domain)."
  tag severity: "medium"
  tag severity_source: "unassessed"
  tag nist: ['AC-3', 'CM-5']
  tag ksi:  ['KSI-CMT-RMV', 'KSI-CMT-RVP', 'KSI-IAM-APM', 'KSI-IAM-ELP', 'KSI-IAM-JIT']
  tag nist_r4: ['AC-3', 'CM-5']
  tag cci:  ['CCI-000213', 'CCI-000345']
  tag local_number: "EF-9.3"
  tag srg_source: "DISA Container Platform SRG V2R4 (orchestrator domain, AWS-inherited)"
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
    describe "EF-9.3 AWS-inherited control-plane evidence (no leveraged source configured)" do
      skip "inherited-from-aws: ECS/Fargate control plane is AWS-managed. Set leveraged_evidence_base / inherited_evidence_uri, or `saf attest apply`."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "EF-9.3 AWS authorization evidence (#{uri})" do
      it("is reachable") { expect(doc.connection_error).to be_nil, "evidence unreachable: #{doc.connection_error}" }
      it("exists") { expect(doc.exists?).to eq(true) }
      it("is current within #{max_age_days} days") { expect(doc.current?).to eq(true) }
    end
  end
end
