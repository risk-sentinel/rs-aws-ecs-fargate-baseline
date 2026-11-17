# encoding: UTF-8

control "EF-10.2" do
  title "ECS account-level Container Insights default must be enabled"
  desc  "The account-wide containerInsights default (ecs:ListAccountSettings) "\
        "ensures new clusters get monitoring even if a per-cluster setting is "\
        "missed (AU-6(3)/CA-7). Consumer-configurable, not AWS-inherited."
  tag severity:              "low"
  tag severity_source:       "assessed"
  tag nist:                  ["AU-6 (3)", "CA-7"]
  tag ksi:                   ["KSI-MLA-EVC", "KSI-MLA-OSM"]
  tag nist_r4:               ["AU-6 (3)", "CA-7"]
  tag cci:                   ["CCI-000153", "CCI-000274"]
  tag local_number:          "EF-10.2"
  tag srg_source:            "DISA Container Platform SRG V2R4 (orchestrator config)"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"
  tag exec_validated:        false

  clusters = ecs_cluster_arns
  impact 0.3
  impact 0.0 if clusters.empty?
  only_if("No ECS clusters in scope") { !clusters.empty? }

  # Resolved at CONTROL scope and closed over. A helper mixed into Inspec::Rule
  # is not in scope inside a describe/subject block — the example is not the
  # control — so calling it there raises NameError at exec, which `check` and
  # `json` cannot see because neither evaluates control bodies.
  container_insights = ecs_account_settings.value_for("containerInsights")
  describe "ECS account setting containerInsights" do
    subject { container_insights }
    it { should cmp "enabled" }
  end
end
