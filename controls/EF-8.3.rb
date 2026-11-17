# encoding: UTF-8

control "EF-8.3" do
  title "Clusters must enable Container Insights"
  desc "Container Insights collects metrics/logs needed for monitoring and "\
       "incident response."
  desc  'check', "
    For every ECS cluster in the scan regions, the `containerInsights` setting must be `enabled` or `enhanced`.
  "
  desc  'fix', "
    ```
    aws ecs update-cluster-settings --cluster <cluster> --settings name=containerInsights,value=enhanced
    ```
  "
  tag severity:              "medium"
  tag severity_source:       "unassessed"
  tag nist:                  ["AU-6 (3)"]
  tag ksi:                   ["KSI-MLA-OSM"]
  tag nist_r4:               ["AU-6 (3)"]
  tag cci:                   ["CCI-000153"]
  tag local_number:          "EF-8.3"
  tag fsbp:                  "ECS.12"
  tag cis_source:            "CIS AWS Compute v1.1.0 C-3.9"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  clusters = ecs_cluster_arns
  impact 0.5
  impact 0.0 if clusters.empty?
  only_if("No ECS clusters in scope") { !clusters.empty? }

  clusters.each do |c|
    describe "Container Insights for cluster #{c.split('/').last}" do
      subject { aws_ecs_cluster_full(cluster: c).container_insights_enabled? }
      it { should eq true }
    end
  end
end
