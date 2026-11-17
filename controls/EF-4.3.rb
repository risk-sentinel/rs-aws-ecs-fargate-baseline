# encoding: UTF-8

control "EF-4.3" do
  title "Execution role must not grant wildcard actions"
  desc "The execution role should be scoped to specific ECR / Secrets Manager / "\
       "CloudWatch Logs actions and resources; it must not grant any wildcard "\
       "Action. Deep check parses the role's policy documents."
  desc  'check', "
    For every execution role used by an in-scope Fargate task definition, read the role's inline and attached managed policy documents. No Allow statement may contain an action with `*` in it, whatever its resource.
  "
  desc  'fix', "
    Scope the execution role to the exact actions it needs, for example `ecr:GetAuthorizationToken`, `ecr:BatchGetImage`, `ecr:GetDownloadUrlForLayer`, `logs:CreateLogStream`, `logs:PutLogEvents`, and `secretsmanager:GetSecretValue` on the task's secret ARNs. The AWS managed policy `AmazonECSTaskExecutionRolePolicy` lists actions without wildcards.
  "
  tag severity:              "high"
  tag severity_source:       "assessed"
  tag nist:                  ["AC-6"]
  tag ksi:                   ["KSI-IAM-ELP", "KSI-IAM-JIT"]
  tag nist_r4:               ["AC-6"]
  tag cci:                   ["CCI-000225"]
  tag local_number:          "EF-4.3"
  tag srg:                   "SRG-APP-000033-CTR-000095"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  tds = fargate_task_definition_arns
  role_arns = tds.map { |a| aws_ecs_task_definition_full(task_definition: a).execution_role_arn }.compact.uniq
  impact 0.7
  impact 0.0 if role_arns.empty?
  only_if("No execution roles in scope") { !role_arns.empty? }

  role_arns.each do |role_arn|
    describe "Execution role #{role_name_from_arn(role_arn)}" do
      subject { aws_iam_role_policy_analysis(role_arn: role_arn).wildcard_action_statements }
      it { should be_empty }
    end
  end
end
