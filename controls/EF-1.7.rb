# encoding: UTF-8

control "EF-1.7" do
  title "Task images must not carry findings above the tolerated severity"
  desc "Images with unremediated findings at or above max_image_finding_severity "\
       "must not be deployed. Requires ECR scan results to exist (see EF-1.3)."
  desc  'check', "
    For each in-scope Fargate task image referenced as an ECR image by digest, read its ECR scan findings in the image's own region and registry. The image must have scan results (an unscanned image fails), and the count of findings above the input `max_image_finding_severity` (default HIGH, so CRITICAL by default) must be zero. Not applicable when the ceiling is CRITICAL. Images outside ECR, or referenced by tag alone, are reported as skipped.
  "
  desc  'fix', "
    Rebuild the image on a patched base and with updated dependencies until the scan reports no findings above the ceiling:

    ```
    aws ecr describe-image-scan-findings --repository-name <repo> --image-id imageDigest=<digest>
    ```

    Push the rebuilt image and redeploy from its digest. Accepting a specific finding is a risk decision for the system owner, not a profile setting.
  "
  tag severity:              "high"
  tag severity_source:       "assessed"
  tag nist:                  ["RA-5 a", "SI-2 a"]
  tag ksi:                   ["KSI-CMT-VTD", "KSI-SCR-MON"]
  tag nist_r4:               ["RA-5 a", "SI-2 a"]
  tag cci:                   ["CCI-001054", "CCI-001225"]
  tag local_number:          "EF-1.7"
  tag srg:                   "SRG-APP-000414-CTR-001010"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  rank = %w[INFORMATIONAL LOW MEDIUM HIGH CRITICAL]
  ceiling = input("max_image_finding_severity").to_s.upcase
  ceiling_idx = rank.index(ceiling) || rank.index("HIGH")
  disallowed = rank[(ceiling_idx + 1)..] || []

  images = task_image_refs
  impact 0.7
  impact 0.0 if images.empty? || disallowed.empty?
  only_if("No resolvable ECR images, or ceiling already at CRITICAL") { !images.empty? && !disallowed.empty? }

  unassessable_images(need_digest: true).each do |raw, why|
    describe "Image #{raw}" do
      skip "Not assessed: #{why}."
    end
  end

  images.each do |ref|
    next unless ref[:repo] && ref[:digest]

    img = aws_ecr_image(repository_name: ref[:repo], image_digest: ref[:digest],
                        region: ref[:region], registry_id: ref[:registry_id])
    findings = img.image_scan_findings
    counts = (findings && findings[:finding_severity_counts]) || {}
    over = disallowed.sum { |sev| counts[sev.to_sym].to_i + counts[sev].to_i }
    describe "Disallowed-severity findings (#{disallowed.join('/')}) for #{ref[:repo]}@#{ref[:digest][0, 16]}" do
      subject { over }
      # No scan results is not zero findings: an unscanned image has not been
      # assessed, and passing it would report a clean bill of health.
      it("has scan results") { expect(findings).not_to be_nil, "no ECR scan findings for this image (see EF-1.3)" }
      it { should eq 0 }
    end
  end
end
