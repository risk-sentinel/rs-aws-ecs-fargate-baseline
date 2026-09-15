# encoding: UTF-8
require "aws_backend"

# aws_elbv2_inventory — enumerates Application Load Balancers (ELBv2) with their
# scheme and the FSBP-relevant load-balancer attributes (drop-invalid-headers,
# access logging, deletion protection).
#
# Why custom: the stock `aws_elbs` resource uses the CLASSIC `elb_client` and so
# does not see ALBs at all, and the stock `aws_elasticloadbalancingv2_listeners`
# resource needs a `load_balancer_arn` up front — so something has to enumerate
# the ALBs to drive it. This resource fills that gap using the enumerated
# `elb_client_v2` (the ELBv2 API), filtered to `type == "application"`.
class AwsElbv2Inventory < AwsResourceBase
  include RegionScope
  name "aws_elbv2_inventory"
  desc "Application Load Balancers (ELBv2) with scheme + FSBP attributes, per region."
  example <<~EX
    describe aws_elbv2_inventory(regions: input('scan_regions')).internet_facing do
      it { should_not be_empty }
    end
  EX

  attr_reader :load_balancers

  def initialize(opts = {})
    opts = opts.dup
    # Removed BEFORE super: AwsResourceBase forwards unknown keys to
    # validate_parameters, which raises on anything outside its allow-list.
    region_override = Array(opts.delete(:regions))
    super(opts)
    validate_parameters(allow: %i(aws_region aws_endpoint))
    # ELBv2 is regional. A load balancer in another region was never listed, so
    # every FSBP assertion scoped on this inventory passed against an empty set
    # -- including the internet-facing TLS checks, where an unlisted edge LB is
    # exactly the one that matters.
    @all_regions = region_scope_or_fail!(@aws, region_override)
    @load_balancers = fetch_load_balancers
  end

  def fetch_load_balancers
    out = []
    each_region_client(::Aws::ElasticLoadBalancingV2::Client) do |client, region|
      client.describe_load_balancers.each do |page|
        page.load_balancers.each do |lb|
          next unless lb.type == "application"

          attrs = {}
          begin
            client.describe_load_balancer_attributes(load_balancer_arn: lb.load_balancer_arn)
                  .attributes.each { |a| attrs[a.key] = a.value }
          rescue ::Aws::Errors::ServiceError => e
            # One unreadable LB must not drop the rest of the region. Recorded
            # so the gap is visible instead of looking like a compliant default.
            region_errors[region] = "describe_load_balancer_attributes(#{lb.load_balancer_name}): #{e.message}"
          end

          out << {
            arn:                  lb.load_balancer_arn,
            name:                 lb.load_balancer_name,
            # The region is carried on every row: a finding on an LB is
            # meaningless without saying where it lives.
            region:               region,
            scheme:               lb.scheme,
            drop_invalid_headers: attrs["routing.http.drop_invalid_header_fields.enabled"] == "true",
            access_logs_enabled:  attrs["access_logs.s3.enabled"] == "true",
            deletion_protection:  attrs["deletion_protection.enabled"] == "true",
          }
        end
      end
    end
    out
  end

  # internet-facing ALBs — the ones that terminate client TLS at the edge.
  def internet_facing
    @load_balancers.select { |lb| lb[:scheme] == "internet-facing" }
  end

  def arns
    @load_balancers.map { |lb| lb[:arn] }
  end

  def to_s
    "ELBv2 Inventory (#{@load_balancers.size} application LBs across " \
      "#{regions_scanned.length} region(s))"
  end
end
