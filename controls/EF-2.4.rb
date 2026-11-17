# encoding: UTF-8

control "EF-2.4" do
  title "Containers must drop ALL Linux capabilities and add only an allowlist"
  desc "linuxParameters.capabilities.drop must include ALL; any added "\
       "capability must be in allowed_added_capabilities (least privilege)."
  desc  'check', "
    Examines the latest ACTIVE revision of every Fargate task definition in the scan regions (`scan_regions`). Every container's `linuxParameters.capabilities.drop` must include `ALL`, and every capability in `linuxParameters.capabilities.add` must be listed in the input `allowed_added_capabilities`.
  "
  desc  'fix', "
    In each container definition set:

    ```
    \"linuxParameters\": { \"capabilities\": { \"drop\": [\"ALL\"], \"add\": [<only capabilities in allowed_added_capabilities>] } }
    ```

    Register a new task definition revision with the change (`aws ecs register-task-definition --cli-input-json file://taskdef.json`), then update the service to use it (`aws ecs update-service --cluster <cluster> --service <service> --task-definition <family>:<revision>`).
  "
  tag severity:              "medium"
  tag severity_source:       "unassessed"
  tag nist:                  ['AC-6', 'CM-7 a']
  tag ksi:                   ['KSI-CMT-RMV', 'KSI-IAM-ELP', 'KSI-IAM-JIT']
  tag nist_r4:               ['AC-6', 'CM-7 a']
  tag cci:                   ['CCI-000225', 'CCI-000381']
  tag local_number:          "EF-2.4"
  tag srg:                   "SRG-APP-000342-CTR-000775"
  tag nist_800_190:          "4.5.3"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  allowed = input("allowed_added_capabilities")
  tds = fargate_task_definition_arns
  impact 0.5
  impact 0.0 if tds.empty?
  only_if("No Fargate task definitions in scope") { !tds.empty? }

  tds.each do |arn|
    td = aws_ecs_task_definition_full(task_definition: arn)
    describe "Containers not dropping ALL caps in #{td.family}:#{td.revision}" do
      subject { td.containers_without_dropped_all_caps }
      it { should be_empty }
    end
    describe "Containers adding disallowed caps in #{td.family}:#{td.revision}" do
      subject { td.containers_with_disallowed_added_caps(allowed) }
      it { should be_empty }
    end
  end
end
