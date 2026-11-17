# encoding: UTF-8

control "EF-10.4" do
  title "Task base images must be current (no EOL / out-of-cadence base image)"
  desc  "Base-image OS-package currency / EOL is an image-build-pipeline concern "\
        "not assertable from the running task definition (the image digest does not "\
        "carry an EOL date). Converted to Pass-with-evidence against the boundary's "\
        "image-build / SBOM-currency record. EF-1.7 (scan findings) provides "\
        "detective coverage of known-vulnerable packages."
  desc  'check', "
    Attestation. Resolve the boundary's base-image currency record: the input `c_ef_10_4_attestation_uri`, or else the `EF-10.4` entry under `boundary_docs_base`. It must be reachable, exist, and be no older than `attestation_max_age_days` (default 365). When no location is configured, the control is skipped with instructions. EF-1.7 gives detective coverage of known-vulnerable packages.
  "
  desc  'fix', "
    Keep a record from the image build pipeline showing each base image is supported (not end of life) and rebuilt on a set cadence, for example SBOM currency reports and the rebuild schedule. Publish it where the scanner can read it and set `boundary_docs_base` or `c_ef_10_4_attestation_uri`. Alternatively, record a CMS-pattern attestation with `saf attest apply`.
  "
  tag severity:              "medium"
  tag severity_source:       "unassessed"
  tag nist:                  ["SI-2 c"]
  tag ksi:                   ["KSI-CMT-VTD"]
  tag nist_r4:               ["SI-2 c"]
  tag cci:                   ["CCI-002605"]
  tag local_number:          "EF-10.4"
  tag srg_source:            "DISA Container Platform SRG V2R4 (image currency)"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "alternative"
  tag attestation_category:  "policy"
  tag exec_validated:        false

  impact 0.5

  uri = input("c_ef_10_4_attestation_uri", value: "")
  uri = attestation_uri(:boundary, "EF-10.4") if uri.to_s.empty?
  max_age_days = input("attestation_max_age_days", value: 365)

  if uri.to_s.empty?
    describe "EF-10.4 base-image currency attestation" do
      skip "attestation-required: base-image EOL / OS-package currency is an "\
           "image-build-pipeline concern. Set boundary_docs_base / "\
           "c_ef_10_4_attestation_uri to the image-build / SBOM-currency record, "\
           "or supply a CMS-pattern attestation via `saf attest apply`. EF-1.7 "\
           "gives detective coverage of known-vulnerable packages."
    end
  else
    doc = document_attestation(uri, max_age_days: max_age_days)
    describe "EF-10.4 base-image currency attestation (#{uri})" do
      it("is reachable") { expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}" }
      it("exists") { expect(doc.exists?).to eq(true) }
      it("is current within #{max_age_days} days") { expect(doc.current?).to eq(true) }
    end
  end
end
