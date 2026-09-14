# ECS inventory helper — returns flat iterables suited for control
# describes:
#
#   aws_ecs_inventory.cluster_arns
#     => [<cluster-arn>, ...]
#
#   aws_ecs_inventory.service_keys
#     => [{cluster: <cluster-arn>, service: <service-arn>}, ...]
#
#   aws_ecs_inventory.latest_active_task_definition_arns
#     => [<arn>, ...]  # one per family, highest revision, status=ACTIVE
#
# Why not vendored `aws_ecs_task_definitions`: it lists every revision
# of every family, which inflates iteration cost and flags old revisions
# that are no longer deployable. CIS intent is "latest active revision",
# which is what this helper returns.

class AwsEcsInventory < AwsResourceBase
  include RegionScope
  name "aws_ecs_inventory"
  desc "ECS inventory: clusters, services, latest-ACTIVE task definitions."

  example "
    describe aws_ecs_inventory do
      its('cluster_arns') { should_not be_empty }
    end
  "

  attr_reader :cluster_arns

  def initialize(opts = {})
    opts = opts.dup
    # Removed BEFORE super: AwsResourceBase forwards unknown keys to
    # validate_parameters, which raises on anything outside its allow-list.
    region_override = Array(opts.delete(:regions))
    super(opts)
    validate_parameters
    # ECS is regional. A cluster in another region was simply never listed, and
    # every control scoped on this inventory passed against an empty set.
    @all_regions = region_scope_or_fail!(@aws, region_override)
    @cluster_arns = fetch_cluster_arns
  end

  def fetch_cluster_arns
    arns = []
    each_region_client(::Aws::ECS::Client) do |client, _region|
      token = nil
      loop do
        args = {}
        args[:next_token] = token if token
        resp = client.list_clusters(args)
        break unless resp
        # A cluster ARN carries its own region, so the region stays visible in
        # the evidence without a parallel structure to keep in sync.
        arns.concat(resp.cluster_arns)
        token = resp.next_token
        break unless token
      end
    end
    arns
  end

  # A cluster ARN carries its own region, so calls scoped to a cluster must use a
  # client bound to THAT region. Going through @aws.ecs_client would send a
  # us-west-2 cluster's request to the default region and get nothing back --
  # the control would then report a cluster with no services.
  def ecs_client_for(arn)
    r = client_region_for(arn)
    return ::Aws::ECS::Client.new(region: r) if r
    @aws.ecs_client
  end

  def service_keys
    @service_keys ||= @cluster_arns.flat_map do |cluster_arn|
      arns = []
      token = nil
      loop do
        resp = nil
        catch_aws_errors do
          args = { cluster: cluster_arn }
          args[:next_token] = token if token
          resp = ecs_client_for(cluster_arn).list_services(args)
        end
        break unless resp
        arns.concat(resp.service_arns)
        token = resp.next_token
        break unless token
      end
      arns.map { |s| { cluster: cluster_arn, service: s } }
    end
  end

  # Task definitions are a REGIONAL registry, not a per-cluster one, so they are
  # enumerated per region like clusters are.
  def task_def_client
    @task_def_client || @aws.ecs_client
  end

  def latest_active_task_definition_arns
    @latest_active_task_definition_arns ||= begin
      all = []
      each_region_client(::Aws::ECS::Client) do |client, _region|
        @task_def_client = client
        all.concat(task_definition_arns_in_region)
      end
      @task_def_client = nil
      all
    end
  end

  def task_definition_arns_in_region
    begin
      families = []
      token = nil
      loop do
        resp = nil
        catch_aws_errors do
          args = { status: "ACTIVE" }
          args[:next_token] = token if token
          resp = task_def_client.list_task_definition_families(args)
        end
        break unless resp
        families.concat(resp.families)
        token = resp.next_token
        break unless token
      end
      families.flat_map do |family|
        resp = nil
        catch_aws_errors do
          resp = task_def_client.list_task_definitions(
            family_prefix: family,
            status:        "ACTIVE",
            sort:          "DESC",
            max_results:   1,
          )
        end
        resp&.task_definition_arns&.first
      end.compact
    end
  end

  def to_s
    "AWS ECS inventory (clusters=#{@cluster_arns.size})"
  end
end
