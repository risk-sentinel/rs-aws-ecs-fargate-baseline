# encoding: UTF-8

control "EF-8.7" do
  title "CloudWatch log groups for tasks must set a retention policy"
  desc "Each CloudWatch Logs group referenced by an awslogs-driver container "\
       "must have an explicit retention policy of at least "\
       "`min_log_retention_days` days, so audit-record storage capacity is "\
       "allocated and bounded rather than left to never-expire (AU-4 — allocate "\
       "audit-record storage capacity). A never-expire (unset) group fails."
  desc  'check', "
    For every CloudWatch Logs group named in an `awslogs` container's `awslogs-group` option across in-scope Fargate task definitions, the group must have a retention policy (`retentionInDays` set, not Never expire) of at least the input `min_log_retention_days` (default 30). A group that does not exist fails.
  "
  desc  'fix', "
    ```
    aws logs put-retention-policy --log-group-name <group> --retention-in-days <days>
    ```

    Choose a retention period that meets the system's audit-record retention requirement and is at least `min_log_retention_days`.
  "
  tag severity:              "low"
  tag severity_source:       "assessed"
  tag nist:                  ['AU-11', 'AU-4']
  tag ksi:                   ['KSI-MLA-OSM']
  tag nist_r4:               ['AU-11', 'AU-4']
  tag cci:                   ['CCI-000167', 'CCI-001849']
  tag local_number:          "EF-8.7"
  tag srg:                   "SRG-APP-000357-CTR-000800"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  tds    = fargate_task_definition_arns
  groups = tds.flat_map { |a| aws_ecs_task_definition_full(task_definition: a).awslogs_group_names }.compact.uniq
  min    = input("min_log_retention_days", value: 30)
  impact 0.3
  impact 0.0 if groups.empty?
  only_if("No awslogs CloudWatch log groups referenced by Fargate task defs") { !groups.empty? }

  groups.each do |g|
    lg        = aws_cloudwatch_log_group(log_group_name: g)
    retention = lg.exists? ? lg.retention_in_days : nil
    describe "CloudWatch log group #{g} retention (days)" do
      subject { retention }
      it "is set (not never-expire)" do
        expect(retention).not_to be_nil
      end
      it "is at least #{min} days" do
        expect(retention.to_i).to be >= min.to_i
      end
    end
  end
end
