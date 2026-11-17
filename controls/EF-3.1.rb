# encoding: UTF-8

control "EF-3.1" do
  title "Secrets must not be passed as plaintext environment variables"
  desc "Secret-shaped values in container environment[] are visible in the "\
       "task definition. Use the secrets[] block with Secrets Manager / SSM "\
       "instead (CM-2/IA-5)."
  desc  'check', "
    Examines the latest ACTIVE revision of every Fargate task definition in the scan regions (`scan_regions`). No container's `environment` may contain a variable whose name looks like a secret: matching password, passwd, secret, token, api key, access key or private key, case-insensitively.
  "
  desc  'fix', "
    Store each such value in AWS Secrets Manager or SSM Parameter Store and move it from `environment` to the container's `secrets` block:

    ```
    \"secrets\": [ { \"name\": \"DB_PASSWORD\", \"valueFrom\": \"arn:aws:secretsmanager:<region>:<account>:secret:<name>\" } ]
    ```

    Grant the execution role read access to that secret or parameter only. Register a new task definition revision with the change (`aws ecs register-task-definition --cli-input-json file://taskdef.json`), then update the service to use it (`aws ecs update-service --cluster <cluster> --service <service> --task-definition <family>:<revision>`).
  "
  tag severity:              "high"
  tag severity_source:       "assessed"
  tag nist:                  ["SC-28", "CM-6 b"]
  tag ksi:                   ["KSI-CMT-LMC", "KSI-CMT-RMV", "KSI-MLA-EVC", "KSI-SVC-ACM", "KSI-SVC-SIN"]
  tag nist_r4:               ["CM-6 b", "SC-28"]
  tag cci:                   ["CCI-001199", "CCI-000366"]
  tag local_number:          "EF-3.1"
  tag srg:                   "SRG-APP-000038-CTR-000105"
  tag fsbp:                  "ECS.8"
  tag cis_source:            "CIS AWS Compute v1.1.0 C-3.6"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  tds = fargate_task_definition_arns
  impact 0.7
  impact 0.0 if tds.empty?
  only_if("No Fargate task definitions in scope") { !tds.empty? }

  tds.each do |arn|
    td = aws_ecs_task_definition_full(task_definition: arn)
    describe "Secret-shaped env vars in #{td.family}:#{td.revision}" do
      subject { td.containers_with_secret_shaped_env }
      it { should be_empty }
    end
  end
end
