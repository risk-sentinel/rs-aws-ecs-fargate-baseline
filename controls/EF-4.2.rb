# encoding: UTF-8

control "EF-4.2" do
  title "Task role must not grant wildcard action on wildcard resource"
  desc "The task role's policies must not contain Allow statements pairing a "\
       "wildcard Action with a wildcard Resource (an over-broad grant). Deep check "\
       "parses inline + attached managed policy documents."
  desc  'check', "
    For every task role used by an in-scope Fargate task definition, read the role's inline and attached managed policy documents. No Allow statement may combine an action containing `*` with a `Resource` of `*`.
  "
  desc  'fix', "
    Replace wildcard grants with the specific actions and resource ARNs the application uses. IAM Access Analyzer policy generation (`aws accessanalyzer start-policy-generation`) can draft a policy from the role's CloudTrail activity. Update the policy with `aws iam put-role-policy` (inline) or a new managed policy version.
  "
  tag severity:              "high"
  tag severity_source:       "assessed"
  tag nist:                  ["AC-6"]
  tag ksi:                   ["KSI-IAM-ELP", "KSI-IAM-JIT"]
  tag nist_r4:               ["AC-6"]
  tag cci:                   ["CCI-000225"]
  tag local_number:          "EF-4.2"
  tag srg:                   "SRG-APP-000033-CTR-000095"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  tds = fargate_task_definition_arns
  role_arns = tds.map { |a| aws_ecs_task_definition_full(task_definition: a).task_role_arn }.compact.uniq
  impact 0.7
  impact 0.0 if role_arns.empty?
  only_if("No task roles in scope") { !role_arns.empty? }

  role_arns.each do |role_arn|
    describe "Task role #{role_name_from_arn(role_arn)}" do
      subject { aws_iam_role_policy_analysis(role_arn: role_arn).wildcard_statements }
      it { should be_empty }
    end
  end
end
