# encoding: UTF-8

control "EF-10.3" do
  title "Fargate task definitions must pin runtimePlatform"
  desc  "operatingSystemFamily + cpuArchitecture must be explicitly set so the "\
        "runtime/image expectation is deterministic across deploys (CM-6 b). "\
        "Consumer-configurable on the task definition."
  desc  'check', "
    Examines the latest ACTIVE revision of every Fargate task definition in the scan regions (`scan_regions`). The task definition's `runtimePlatform` must set both `operatingSystemFamily` and `cpuArchitecture`.
  "
  desc  'fix', "
    Add to the task definition, matching the image:

    ```
    \"runtimePlatform\": { \"operatingSystemFamily\": \"LINUX\", \"cpuArchitecture\": \"X86_64\" }
    ```

    Register a new task definition revision with the change (`aws ecs register-task-definition --cli-input-json file://taskdef.json`), then update the service to use it (`aws ecs update-service --cluster <cluster> --service <service> --task-definition <family>:<revision>`).
  "
  tag severity:              "low"
  tag severity_source:       "assessed"
  tag nist:                  ["CM-6 b"]
  tag ksi:                   ["KSI-CMT-LMC", "KSI-CMT-RMV", "KSI-MLA-EVC", "KSI-SVC-ACM"]
  tag nist_r4:               ["CM-6 b"]
  tag cci:                   ["CCI-000366"]
  tag local_number:          "EF-10.3"
  tag srg_source:            "DISA Container Platform SRG V2R4 (image/runtime config)"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"
  tag exec_validated:        false

  task_defs = fargate_task_definition_arns
  impact 0.3
  impact 0.0 if task_defs.empty?
  only_if("No Fargate task definitions in scope") { !task_defs.empty? }

  task_defs.each do |arn|
    describe "runtimePlatform pinned for #{arn.split('/').last}" do
      subject { aws_ecs_task_definition_full(task_definition: arn).runtime_platform_pinned? }
      it { should eq true }
    end
  end
end
