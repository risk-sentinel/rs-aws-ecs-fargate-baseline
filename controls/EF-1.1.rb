# encoding: UTF-8

control "EF-1.1" do
  title "Container images must be pinned by digest (not a mutable tag)"
  desc "Images referenced by mutable tag (or :latest) can change underneath a "\
       "deployment. Pin by @sha256 digest for immutable, verifiable provenance."
  tag severity:              "medium"
  tag severity_source:       "unassessed"
  tag nist:                  ['CM-2 (2)']
  tag ksi:                   ['KSI-PIY-GIV', 'KSI-SVC-ACM', 'KSI-SVC-VRI']
  tag nist_r4:               ['CM-2 (2)']
  tag cci:                   ['CCI-000302']
  tag local_number:          "EF-1.1"
  tag srg:                   "SRG-APP-000131-CTR-000285"
  tag nist_800_190:          "4.1"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  require_pin = input("require_image_digest_pinning")
  tds = fargate_task_definition_arns
  applicable = require_pin && !tds.empty?
  impact 0.5
  impact 0.0 unless applicable
  only_if("digest pinning not required or no Fargate task defs") { applicable }

  tds.each do |arn|
    td = aws_ecs_task_definition_full(task_definition: arn)
    describe "Unpinned images in #{td.family}:#{td.revision}" do
      subject { td.unpinned_image_containers }
      it { should be_empty }
    end
  end
end
