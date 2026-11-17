# encoding: UTF-8

control "EF-4.1" do
  title "Task role must be distinct from the execution role"
  desc "The execution role (image pull, log push, secret fetch) and the task "\
       "role (application AWS permissions) must be separate so the application "\
       "does not inherit infrastructure permissions (AC-5/AC-6, 800-190 §4.5)."
  tag severity:              "medium"
  tag severity_source:       "unassessed"
  tag nist:                  ['AC-6', 'AC-5 b']
  tag ksi:                   ['KSI-IAM-ELP', 'KSI-IAM-JIT', 'KSI-PIY-RIS', 'KSI-PIY-RSD']
  tag nist_r4:               ['AC-5 c', 'AC-6']
  tag cci:                   ['CCI-000225', 'CCI-002220']
  tag local_number:          "EF-4.1"
  tag srg:                   "SRG-APP-000342-CTR-000775"
  tag nist_800_190:          "4.5"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  tds = fargate_task_definition_arns
  impact 0.5
  impact 0.0 if tds.empty?
  only_if("No Fargate task definitions in scope") { !tds.empty? }

  tds.each do |arn|
    td = aws_ecs_task_definition_full(task_definition: arn)
    describe "Role separation for #{td.family}:#{td.revision}" do
      it "must define a task role distinct from the execution role" do
        expect(td.task_role_arn).not_to be_nil
        expect(td.execution_role_arn).not_to be_nil
        expect(td.task_role_arn).not_to eq(td.execution_role_arn)
      end
    end
  end
end
