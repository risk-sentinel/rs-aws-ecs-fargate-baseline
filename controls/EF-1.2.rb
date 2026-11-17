# encoding: UTF-8

control "EF-1.2" do
  title "Container images must come from trusted registries"
  desc "Only images from approved registries (private ECR or vetted sources) "\
       "may be deployed. Fails closed when trusted_image_registries is empty."
  tag severity:              "high"
  tag severity_source:       "assessed"
  tag nist:                  ['CM-7 (5) (b)', 'CM-7 a']
  tag ksi:                   ['KSI-CMT-RMV', 'KSI-IAM-JIT', 'KSI-PIY-GIV']
  tag nist_r4:               ['CM-7 (5) (b)', 'CM-7 a']
  tag cci:                   ['CCI-001774', 'CCI-000381']
  tag local_number:          "EF-1.2"
  tag srg:                   "SRG-APP-000141-CTR-000320"
  tag fsbp:                  "n/a"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  trusted = input("trusted_image_registries")
  tds = fargate_task_definition_arns
  impact 0.7
  impact 0.0 if tds.empty?
  only_if("No Fargate task definitions in scope") { !tds.empty? }

  tds.each do |arn|
    td = aws_ecs_task_definition_full(task_definition: arn)
    describe "Untrusted images in #{td.family}:#{td.revision}" do
      subject { td.untrusted_image_containers(trusted) }
      it { should be_empty }
    end
  end
end
