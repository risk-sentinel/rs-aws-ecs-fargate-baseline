# encoding: UTF-8

control "EF-10.1" do
  title "GuardDuty Runtime Monitoring must cover ECS/Fargate"
  desc  "GuardDuty Runtime Monitoring provides runtime threat detection for Fargate "\
        "tasks. It is consumer-configurable (not AWS-inherited) and must be enabled "\
        "where ECS is in use."
  desc  'check', "
    For every region that has an in-scope ECS cluster, GuardDuty must have an `ENABLED` detector whose `RUNTIME_MONITORING` feature is `ENABLED` with its `ECS_FARGATE_AGENT_MANAGEMENT` configuration `ENABLED`. Without agent management, Fargate tasks get no GuardDuty agent. A region whose detectors cannot be read fails as unreadable, not as covered.
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

  # GuardDuty is regional: check every region that runs an in-scope cluster.
  regions = clusters.map { |arn| arn.split(":")[3] }.compact.uniq
  coverage = aws_guardduty_ecs_coverage(regions: regions)
  describe coverage do
    its("unreadable_regions") { should be_empty }
    its("uncovered_regions") { should be_empty }
  end
end
