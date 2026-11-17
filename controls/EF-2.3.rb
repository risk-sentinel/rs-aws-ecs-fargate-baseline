# encoding: UTF-8

control "EF-2.3" do
  title "Containers must use a read-only root filesystem"
  desc "readonlyRootFilesystem=true prevents tampering with the container "\
       "filesystem at runtime (AC-6/CM-7)."
  tag severity:              "medium"
  tag severity_source:       "unassessed"
  tag nist:                  ['AC-6', 'CM-7 b']
  tag ksi:                   ['KSI-CMT-RMV', 'KSI-IAM-ELP', 'KSI-IAM-JIT']
  tag nist_r4:               ['AC-6', 'CM-7 b']
  tag cci:                   ['CCI-000225', 'CCI-000382']
  tag local_number:          "EF-2.3"
  tag srg:                   "SRG-APP-000133-CTR-000295"
  tag fsbp:                  "ECS.5"
  tag cis_source:            "CIS AWS Compute v1.1.0 C-3.5"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  tds = fargate_task_definition_arns
  impact 0.5
  impact 0.0 if tds.empty?
  only_if("No Fargate task definitions in scope") { !tds.empty? }

  tds.each do |arn|
    td = aws_ecs_task_definition_full(task_definition: arn)
    describe "Writable-root-fs containers in #{td.family}:#{td.revision}" do
      subject { td.non_readonly_root_fs_container_names }
      it { should be_empty }
    end
  end
end
