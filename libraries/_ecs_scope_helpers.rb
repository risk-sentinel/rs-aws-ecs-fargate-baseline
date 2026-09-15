# encoding: UTF-8
#
# Helpers mixed into the InSpec control-eval context so controls stay terse.
#
#   fargate_task_definition_arns  -> latest-ACTIVE task defs that require FARGATE
#   ecs_service_keys              -> [{cluster:, service:}, ...]
#   ecs_cluster_arns              -> [<cluster-arn>, ...]
#   role_name_from_arn(arn)       -> trailing role name
#
# Scope is limited to Fargate: a task definition is in scope only when its
# requiresCompatibilities includes FARGATE. EC2-launch-type task defs and
# their host-level concerns are out of scope for a Fargate baseline (those
# belong to cis-aws-compute / host-OS profiles).
module EcsScopeHelpers
  # Raised when the profile was given no region scope. NOT rescued by the
  # helpers below, deliberately -- see the note on the rescues.
  class ScopeNotSupplied < StandardError; end

  # The regions the consumer put in scope.
  #
  # An InSpec RESOURCE cannot read inputs -- `input()` raises in resource scope.
  # These helpers are mixed into the control-eval context, which can, so the
  # region scope has to be threaded from here into every regional resource.
  # Nothing did that before: aws_ecs_inventory was constructed with no `regions:`
  # at all, so its fail-closed check tripped on every real exec.
  def scan_regions_in_scope
    Array(input("scan_regions")).map(&:to_s).map(&:strip).reject(&:empty?)
  end

  def ecs_scope_regions!
    regions = scan_regions_in_scope
    return regions unless regions.empty?

    raise ScopeNotSupplied,
          "no scan_regions supplied -- refusing to report an empty ECS scope " \
          "that cannot be distinguished from an account with no clusters. Set " \
          "scan_regions to the regions in scope, or to [\"*\"] to sweep the partition."
  end

  # The rescues below return [] for a genuinely empty account, which is a real
  # and expected state. They must NOT swallow ScopeNotSupplied: "we looked in
  # the right regions and found no clusters" and "nobody told us which regions
  # to look in" both produced [] before, and [] makes every dependent control
  # go Not Applicable with the message "No ECS clusters in scope". That reads as
  # a clean result and is the failure this profile exists to catch.
  def ecs_cluster_arns
    @ecs_cluster_arns ||= aws_ecs_inventory(regions: ecs_scope_regions!).cluster_arns
  rescue ScopeNotSupplied
    raise
  rescue StandardError
    []
  end

  def ecs_service_keys
    @ecs_service_keys ||= aws_ecs_inventory(regions: ecs_scope_regions!).service_keys
  rescue ScopeNotSupplied
    raise
  rescue StandardError
    []
  end

  def fargate_task_definition_arns
    @fargate_task_definition_arns ||= begin
      aws_ecs_inventory(regions: ecs_scope_regions!).latest_active_task_definition_arns.select do |arn|
        aws_ecs_task_definition_full(task_definition: arn).fargate?
      end
    rescue ScopeNotSupplied
      raise
    rescue StandardError
      []
    end
  end

  # --- regional resources, region scope threaded once ------------------------
  #
  # Every one of these was previously constructed bare in the controls, so each
  # got whatever single region the client defaulted to. Wrapping them here means
  # the scope is threaded in exactly one place, and memoised: EF-11 asked for
  # aws_elbv2_inventory seven times, which is now seven region sweeps rather
  # than seven cheap reads of a single region.
  #
  # No blanket rescue on these. A regional resource that cannot resolve its
  # scope must fail the control, not hand back an empty set that reads as
  # "nothing to assess here".

  def elbv2_inventory
    @elbv2_inventory ||= aws_elbv2_inventory(regions: ecs_scope_regions!)
  end

  def elbv2_internet_facing
    @elbv2_internet_facing ||= elbv2_inventory.internet_facing
  end

  def ecs_account_settings
    @ecs_account_settings ||= aws_ecs_account_settings(regions: ecs_scope_regions!)
  end

  # Not memoised on subnet_id alone by accident: keyed per subnet, since each
  # call resolves a different one.
  def subnet_routing(subnet_id)
    @subnet_routing ||= {}
    @subnet_routing[subnet_id] ||=
      aws_subnet_routing(subnet_id: subnet_id, regions: ecs_scope_regions!)
  end

  def role_name_from_arn(arn)
    arn.to_s.split("/").last
  end

  # Image references across all Fargate task defs, parsed into
  # {repo:, digest:, registry:, raw:} where the image is an in-account ECR URI:
  #   <acct>.dkr.ecr.<region>.amazonaws.com/<repo>[@sha256:<digest>|:tag]
  # Non-ECR or unparseable images yield repo:/digest: nil.
  def task_image_refs
    @task_image_refs ||= begin
      refs = []
      fargate_task_definition_arns.each do |arn|
        aws_ecs_task_definition_full(task_definition: arn).container_images.each do |img|
          refs << parse_ecr_image(img)
        end
      end
      refs.uniq { |r| r[:raw] }
    rescue ScopeNotSupplied
      raise
    rescue StandardError
      []
    end
  end

  # Distinct in-account ECR repository names backing Fargate task images.
  def ecr_repos_in_scope
    @ecr_repos_in_scope ||= task_image_refs.map { |r| r[:repo] }.compact.uniq
  end

  # Reverse-proxy / web-proxy container images by well-known name.
  PROXY_IMAGE = /nginx|envoy|haproxy|traefik|httpd|\bapache\b|\bproxy\b/i.freeze
  # TLS key material — secret names, env names, or mount paths that carry a
  # certificate / private key (signal that the container terminates TLS).
  TLS_MATERIAL = /tls|ssl|cert|\bkey\b|pem|crt|pkcs/i.freeze

  # Reverse-proxy containers across in-scope Fargate task defs:
  #   [{family:, name:, image:, def: <container-def hash>}, ...]
  def proxy_containers
    @proxy_containers ||= begin
      out = []
      fargate_task_definition_arns.each do |arn|
        td = aws_ecs_task_definition_full(task_definition: arn)
        td.container_definitions.each do |c|
          next unless PROXY_IMAGE.match?(c[:image].to_s) || PROXY_IMAGE.match?(c[:name].to_s)
          out << { family: td.family, name: c[:name], image: c[:image], def: c }
        end
      end
      out
    rescue ScopeNotSupplied
      raise
    rescue StandardError
      []
    end
  end

  # True when a container def has TLS key material wired in — a secret, an env
  # var, or a mounted volume whose name/path looks like a certificate or key.
  # This is the task-def-observable signal that the proxy TERMINATES TLS (it
  # holds the private key); the cipher/protocol config itself is validated inside
  # the container by cis-nginx.
  def container_has_tls_material?(c)
    Array(c[:secrets]).any?     { |s| TLS_MATERIAL.match?(s[:name].to_s) } ||
      Array(c[:environment]).any? { |e| TLS_MATERIAL.match?(e[:name].to_s) } ||
      Array(c[:mount_points]).any? { |m| TLS_MATERIAL.match?(m[:container_path].to_s) || TLS_MATERIAL.match?(m[:source_volume].to_s) }
  end

  def parse_ecr_image(img)
    s = img.to_s
    out = { raw: s, repo: nil, digest: nil, registry: nil }
    # ECR registry host: <acct>.dkr.ecr.<region>.amazonaws.com(.cn)
    if s =~ %r{\A(\d+\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com(?:\.cn)?)/(.+)\z}
      out[:registry] = Regexp.last_match(1)
      remainder = Regexp.last_match(2)
      if remainder.include?("@sha256:")
        repo, digest = remainder.split("@", 2)
        out[:repo] = repo
        out[:digest] = digest
      else
        out[:repo] = remainder.split(":", 2).first
      end
    end
    out
  end
end

# Top-level-qualify `::Inspec::Rule`: library files load inside an anonymous
# class context under InSpec 7, so a bare `Inspec::Rule` resolves relative to
# that class and raises `uninitialized constant Inspec::Rule` at exec time
# (cinc-auditor `check` does not surface this; only `exec`/`json` does). Same
# convention as cis-aws-compute / cis-postgresql.
::Inspec::Rule.include(EcsScopeHelpers)
