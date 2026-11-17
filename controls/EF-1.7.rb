# encoding: UTF-8

control "EF-1.7" do
  title "Task images must not carry findings above the tolerated severity"
  desc "Images with unremediated findings at or above max_image_finding_severity "\
       "must not be deployed (RA-5/SI-2). Requires ECR scan results to exist "\
       "(see EF-1.3)."
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

  images.each do |ref|
    next unless ref[:repo] && ref[:digest]

    img = aws_ecr_image(repository_name: ref[:repo], image_digest: ref[:digest])
    counts = (img.image_scan_findings && img.image_scan_findings[:finding_severity_counts]) || {}
    over = disallowed.sum { |sev| counts[sev.to_sym].to_i + counts[sev].to_i }
    describe "Disallowed-severity findings (#{disallowed.join('/')}) for #{ref[:repo]}@#{ref[:digest][0, 16]}" do
      subject { over }
      it { should eq 0 }
    end
  end
end
