# encoding: UTF-8

control "EF-1.1" do
  title "Container images must be pinned by digest (not a mutable tag)"
  desc "Images referenced by mutable tag (or :latest) can change underneath a "\
       "deployment. Pin by @sha256 digest for immutable, verifiable provenance."
  desc  'check', "
    Examines the latest ACTIVE revision of every Fargate task definition in the scan regions (`scan_regions`). List each container's `image`. Every image reference must include an `@sha256:` digest; a reference by tag alone (`repo:1.2`, `repo:latest`) fails.

    Applies only when the input `require_image_digest_pinning` is true.
  "
  desc  'fix', "
    Resolve each tag to its digest:

    ```
    aws ecr describe-images --repository-name <repo> --image-ids imageTag=<tag> --query 'imageDetails[0].imageDigest'
    ```

    Set the container's `image` to `<registry>/<repo>@sha256:<digest>`. Register a new task definition revision with the change (`aws ecs register-task-definition --cli-input-json file://taskdef.json`), then update the service to use it (`aws ecs update-service --cluster <cluster> --service <service> --task-definition <family>:<revision>`).
  "
  tag severity:              "medium"
  tag severity_source:       "unassessed"
  tag nist:                  ['CM-2 (2)']
  tag ksi:                   ['KSI-PIY-GIV', 'KSI-SVC-ACM', 'KSI-SVC-VRI']
  tag nist_r4:               ['CM-2 (2)']
  tag cci:                   ['CCI-000302']
  tag local_number:          "EF-1.1"
  tag srg:                   "SRG-APP-000131-CTR-000285"
  tag nist_800_190:          "4.1"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  require_pin = input("require_image_digest_pinning")
  tds = fargate_task_definition_arns
  applicable = require_pin && !tds.empty?
  impact 0.5
  impact 0.0 unless applicable
  only_if("digest pinning not required or no Fargate task defs") { applicable }

  tds.each do |arn|
    td = aws_ecs_task_definition_full(task_definition: arn)
    describe "Unpinned images in #{td.family}:#{td.revision}" do
      subject { td.unpinned_image_containers }
      it { should be_empty }
    end
  end
end
