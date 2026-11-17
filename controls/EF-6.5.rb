# encoding: UTF-8

control "EF-6.5" do
  title "Clusters must encrypt Fargate ephemeral storage with a CMK"
  desc "Fargate ephemeral storage should be encrypted with a customer-managed "\
       "KMS key via the cluster's managed storage configuration (SC-28)."
  desc  'check', "
    For every ECS cluster in the scan regions, the cluster's managed storage configuration must name a KMS key for Fargate ephemeral storage (`configuration.managedStorageConfiguration.fargateEphemeralStorageKmsKeyId`).
  "
  desc  'fix', "
    Create or choose a customer managed KMS key whose key policy allows ECS Fargate to use it, then:

    ```
    aws ecs update-cluster --cluster <cluster> --configuration 'managedStorageConfiguration={fargateEphemeralStorageKmsKeyId=<key-arn>}'
    ```

    Tasks launched after the change use the key; replace running tasks with a new deployment.
  "
  tag severity:              "medium"
  tag severity_source:       "unassessed"
  tag nist:                  ['SC-28', 'SC-28 (1)']
  tag ksi:                   ['KSI-SVC-SIN']
  tag nist_r4:               ['SC-28', 'SC-28 (1)']
  tag cci:                   ['CCI-001199', 'CCI-002476']
  tag local_number:          "EF-6.5"
  tag cis_source:            "CIS AWS Compute v1.1.0 C-11.1"
  tag srg:                   "SRG-APP-000429-CTR-001060"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  clusters = ecs_cluster_arns
  impact 0.5
  impact 0.0 if clusters.empty?
  only_if("No ECS clusters in scope") { !clusters.empty? }

  clusters.each do |c|
    describe "Fargate ephemeral storage CMK for cluster #{c.split('/').last}" do
      subject { aws_ecs_cluster_full(cluster: c).fargate_ephemeral_storage_cmk_configured? }
      it { should eq true }
    end
  end
end
