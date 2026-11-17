# encoding: UTF-8

control "EF-6.6" do
  title "Task EFS volumes must enable in-transit encryption"
  desc "Any task definition that mounts an Amazon EFS volume must set "\
       "efsVolumeConfiguration.transitEncryption to ENABLED, so the NFS traffic "\
       "between the task and EFS is TLS-protected. This is the task's east-west "\
       "storage transit, distinct from the north-south ALB/proxy TLS covered by "\
       "EF-11/EF-12. Scoped to task defs that declare EFS volumes."
  desc  'check', "
    Examines the latest ACTIVE revision of every Fargate task definition in the scan regions (`scan_regions`). Applies only to task definitions that declare an Amazon EFS volume. Every EFS volume must set `efsVolumeConfiguration.transitEncryption` to `ENABLED`.
  "
  desc  'fix', "
    Set `\"transitEncryption\": \"ENABLED\"` (and optionally `transitEncryptionPort`) in each volume's `efsVolumeConfiguration`. Register a new task definition revision with the change (`aws ecs register-task-definition --cli-input-json file://taskdef.json`), then update the service to use it (`aws ecs update-service --cluster <cluster> --service <service> --task-definition <family>:<revision>`).
  "
  tag severity:              "high"
  tag severity_source:       "assessed"
  tag nist:                  ['SC-8', 'SC-8 (1)']
  tag ksi:                   ['KSI-CNA-MAT', 'KSI-CNA-ULN', 'KSI-SVC-SIN']
  tag nist_r4:               ['SC-8', 'SC-8 (1)']
  tag cci:                   ['CCI-002418', 'CCI-002421']
  tag local_number:          "EF-6.6"
  tag srg:                   "SRG-APP-000439-CTR-001080"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  arns        = fargate_task_definition_arns
  efs_tds     = arns.select { |a| aws_ecs_task_definition_full(task_definition: a).efs_volumes? }
  impact 0.7
  impact 0.0 if efs_tds.empty?
  only_if("No Fargate task definitions mount an EFS volume") { !efs_tds.empty? }

  efs_tds.each do |arn|
    td       = aws_ecs_task_definition_full(task_definition: arn)
    offenders = td.efs_volumes_without_transit_encryption
    describe "Task #{td.family} EFS volumes with transit encryption ENABLED" do
      subject { offenders }
      it { should be_empty }
    end
  end
end
