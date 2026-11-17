# encoding: UTF-8
#
# aws_ecr_repository — scan + tag-mutability posture of an ECR repository backing a
# Fargate task image (EF-1.3 / EF-1.4). Workload-scoped: the controls iterate only the
# repos referenced by in-scope task definitions (ecr_repos_in_scope). Exposes exactly
# what EF-1 asserts.

class AwsEcrRepository < AwsResourceBase
  name "aws_ecr_repository"
  desc "ECR repository scan-on-push + image-tag-mutability posture."
  example "
    describe aws_ecr_repository(repository_name: 'app') do
      its('scan_on_push') { should eq true }
      its('image_tag_mutability') { should eq 'IMMUTABLE' }
    end
  "

  attr_reader :region, :registry_id, :repository_name, :image_scanning_configuration, :scan_on_push, :image_tag_mutability

  def initialize(opts = {})
    opts = { repository_name: opts } if opts.is_a?(String)
    super(opts)
    validate_parameters(required: %i[repository_name], allow: %i[region registry_id])
    @repository_name = opts[:repository_name]
    @region          = opts[:region].to_s
    @registry_id     = opts[:registry_id].to_s
    @exists = false
    catch_aws_errors do
      # The repository's own region and registry, parsed from the image URI:
      # the scanner's default region and account may hold a different
      # repository of the same name, or none.
      client = @region.empty? ? @aws.ecr_client : ::Aws::ECR::Client.new(region: @region)
      args = { repository_names: [@repository_name] }
      args[:registry_id] = @registry_id unless @registry_id.empty?
      repo = client.describe_repositories(**args).repositories.first
      next if repo.nil?
      @exists                       = true
      @image_scanning_configuration = repo.image_scanning_configuration
      @scan_on_push                 = repo.image_scanning_configuration&.scan_on_push
      @image_tag_mutability         = repo.image_tag_mutability
    end
  end

  def exists?
    @exists == true
  end

  def to_s
    "ECR Repository #{@repository_name}"
  end
end
