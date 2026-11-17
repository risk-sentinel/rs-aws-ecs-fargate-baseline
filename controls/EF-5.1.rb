# encoding: UTF-8

control "EF-5.1" do
  title "Task definitions must use awsvpc network mode"
  desc "Fargate requires awsvpc; asserting it here keeps task-level network "\
       "isolation explicit and portable to non-Fargate consumers."
  desc  'check', "
    Examines the latest ACTIVE revision of every Fargate task definition in the scan regions (`scan_regions`). The task definition's `networkMode` must be `awsvpc`.
  "
  desc  'fix', "
    Set `\"networkMode\": \"awsvpc\"` in the task definition and give the service an `awsvpcConfiguration` with subnets and security groups. Register a new task definition revision with the change (`aws ecs register-task-definition --cli-input-json file://taskdef.json`), then update the service to use it (`aws ecs update-service --cluster <cluster> --service <service> --task-definition <family>:<revision>`).
  "
  tag severity:              "medium"
  tag severity_source:       "unassessed"
  tag nist:                  ["SC-7 a"]
  tag ksi:                   ["KSI-CNA-ULN", "KSI-SVC-EIS"]
  tag nist_r4:               ["SC-7 a"]
  tag cci:                   ["CCI-001097"]
  tag local_number:          "EF-5.1"
  tag srg:                   "SRG-APP-000039-CTR-000110"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  tds = fargate_task_definition_arns
  impact 0.5
  impact 0.0 if tds.empty?
  only_if("No Fargate task definitions in scope") { !tds.empty? }

  tds.each do |arn|
    td = aws_ecs_task_definition_full(task_definition: arn)
    describe "Network mode for #{td.family}:#{td.revision}" do
      subject { td.network_mode }
      it { should eq "awsvpc" }
    end
  end
end
