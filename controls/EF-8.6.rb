# encoding: UTF-8

control "EF-8.6" do
  title "Container logs must ship to a central/off-host driver"
  desc "Each container's logConfiguration.logDriver must be a central, off-host "\
       "driver (awslogs, awsfirelens, or splunk) so audit records are stored "\
       "durably away from the ephemeral task, not on a host-bound driver "\
       "(json-file, journald, syslog, local) that is lost when the task stops "\
       "(AU-4 / AU-9(2) — secondary/central audit storage). EF-8.1 asserts a "\
       "logConfiguration exists; this asserts it off-loads the records."
  tag severity:              "medium"
  tag severity_source:       "unassessed"
  tag nist:                  ['AU-4 (1)', 'AU-9 (2)']
  tag nist_r4:               ['AU-4 (1)', 'AU-9 (2)']
  tag cci:                   ['CCI-001851', 'CCI-001348']
  tag local_number:          "EF-8.6"
  tag srg:                   "SRG-APP-000358-CTR-000805"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  tds = fargate_task_definition_arns
  impact 0.5
  impact 0.0 if tds.empty?
  only_if("No Fargate task definitions in scope") { !tds.empty? }

  tds.each do |arn|
    td = aws_ecs_task_definition_full(task_definition: arn)
    describe "Containers on a local/host-bound log driver in #{td.family}:#{td.revision}" do
      subject { td.containers_with_local_log_driver }
      it { should be_empty }
    end
  end
end
