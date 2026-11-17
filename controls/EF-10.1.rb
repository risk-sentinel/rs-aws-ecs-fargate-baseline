# encoding: UTF-8

control "EF-10.1" do
  title "GuardDuty Runtime Monitoring must cover ECS/Fargate"
  desc  "GuardDuty Runtime Monitoring provides runtime threat detection for "\
        "Fargate tasks. It is consumer-configurable (not AWS-inherited) and must "\
        "be enabled where ECS is in use (SI-4 / AU-6)."
  desc  'check', "
    When any ECS cluster is in scope, list the account's GuardDuty detectors. At least one detector must be `ENABLED` with its `RUNTIME_MONITORING` feature `ENABLED`.
  "
  desc  'fix', "
    ```
    aws guardduty update-detector --detector-id <id> --features '[{\"Name\":\"RUNTIME_MONITORING\",\"Status\":\"ENABLED\",\"AdditionalConfiguration\":[{\"Name\":\"ECS_FARGATE_AGENT_MANAGEMENT\",\"Status\":\"ENABLED\"}]}]'
    ```

    Repeat in each region that runs ECS, or enable it organization-wide from the GuardDuty delegated administrator.
  "
  tag severity:              "medium"
  tag severity_source:       "unassessed"
  tag nist:                  ['SI-4 a 1', 'SI-4 (2)']
  tag ksi:                   ['KSI-MLA-OSM', 'KSI-MLA-RVL', 'KSI-SVC-EIS']
  tag nist_r4:               ['SI-4 (2)', 'SI-4 a 1']
  tag cci:                   ['CCI-002641', 'CCI-001260']
  tag local_number:          "EF-10.1"
  tag srg_source:            "DISA Container Platform SRG V2R4 (runtime monitoring)"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"
  tag exec_validated:        false

  clusters = ecs_cluster_arns
  impact 0.5
  impact 0.0 if clusters.empty?
  only_if("No ECS clusters in scope") { !clusters.empty? }

  describe aws_guardduty_ecs_coverage do
    it { should be_runtime_monitoring_enabled }
  end
end
