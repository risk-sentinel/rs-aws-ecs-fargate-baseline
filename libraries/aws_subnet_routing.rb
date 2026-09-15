# NOTE on the client accessor: EC2's is `compute_client`, NOT `ec2_client`.
# AwsConnection defines roughly sixty explicit <service>_client methods and has
# no method_missing -- the ones in this resource pack are on AwsResourceBase,
# AwsResourceProbe and NullResponse, none of which are in the lookup path for
# `@aws.<something>`. `@aws.ec2_client` therefore raises NoMethodError, and
# neither `cinc-auditor check` nor `json` can see it: both only LOAD the
# resource, and the call sits inside fetch-time code.
require "aws_backend"

# aws_subnet_routing — resolves the EFFECTIVE route table for a subnet and
# answers whether it has a default route (0.0.0.0/0 or ::/0) to an internet
# gateway. AWS uses the subnet's explicitly associated route table if one
# exists, otherwise the VPC main route table. The vendored aws_route_table
# only takes route_table_id and does no subnet->table resolution, which is
# what EF-5.4 (private-subnet check) needs. Uses the enumerated ec2_client.
class AwsSubnetRouting < AwsResourceBase
  include RegionScope
  name "aws_subnet_routing"
  desc "Effective route table + internet-egress posture for a subnet."
  example <<~EX
    describe aws_subnet_routing(subnet_id: 'subnet-123', regions: input('scan_regions')) do
      it { should_not have_internet_gateway_route }
    end
  EX

  attr_reader :subnet_id, :vpc_id, :route_table_id, :routes, :region

  # This resource RESOLVES one subnet rather than sweeping, so it searches the
  # region scope until it finds the subnet, then does the route-table lookups in
  # that same region. A subnet id does not encode its region, so a single-region
  # client could only ever resolve subnets that happened to live in the client's
  # default region -- for anything else `exists?` was false and EF-5.4 read it as
  # "subnet has no internet route", which is indistinguishable from a private
  # subnet and is the wrong answer for a public one.
  #
  # Not finding the subnet after searching every region in scope is a real
  # answer. Not having searched is not. `searched_regions` records which is which.
  def initialize(opts = {})
    opts = { subnet_id: opts } if opts.is_a?(String)
    opts = opts.dup
    # Removed BEFORE super: AwsResourceBase forwards unknown keys to
    # validate_parameters, which raises on anything outside its allow-list.
    region_override = Array(opts.delete(:regions))
    super(opts)
    validate_parameters(required: %i(subnet_id))
    @subnet_id = opts[:subnet_id]
    @routes = []
    @exists = false
    @region = nil
    @all_regions = region_scope_or_fail!(@aws, region_override)
    locate_subnet
  end

  def exists?
    @exists
  end

  # Regions actually queried for this subnet. Empty means the search never ran,
  # which is a different failure from "searched and absent".
  def searched_regions
    regions_scanned
  end

  private

  def locate_subnet
    each_region_client(::Aws::EC2::Client) do |client, region|
      next if @exists

      subnet = find_subnet(client)
      next if subnet.nil?

      @exists = true
      @region = region
      @vpc_id = subnet.vpc_id
      resolve_route_table(client)
    end
  end

  # A subnet absent from a region is the normal case while searching, not an
  # error, so it is swallowed HERE -- inside the block -- rather than reaching
  # each_region_client's rescue, which would record it in region_errors and
  # report every region we looked in as broken.
  def find_subnet(client)
    client.describe_subnets(subnet_ids: [@subnet_id]).subnets.first
  rescue ::Aws::EC2::Errors::InvalidSubnetIDNotFound
    nil
  rescue ::Aws::Errors::ServiceError
    nil
  end

  public

  # True if the effective route table sends 0.0.0.0/0 (or ::/0) to an
  # internet gateway — i.e. the subnet is public.
  def internet_gateway_route?
    @routes.any? do |r|
      default = ["0.0.0.0/0", "::/0"].include?(r[:destination].to_s)
      default && r[:gateway_id].to_s.start_with?("igw-")
    end
  end

  def to_s
    where = @region ? " in #{@region}" : " (not found in #{searched_regions.length} region(s))"
    "Subnet routing #{@subnet_id}#{where}"
  end

  private

  def resolve_route_table(client)
    return if @vpc_id.nil?

    explicit = client.describe_route_tables(
      filters: [{ name: "association.subnet-id", values: [@subnet_id] }],
    ).route_tables.first

    table = explicit || main_route_table(client)
    return if table.nil?

    @route_table_id = table.route_table_id
    @routes = table.routes.map do |r|
      {
        destination: r.destination_cidr_block || r.destination_ipv_6_cidr_block,
        gateway_id:  r.gateway_id,
        nat_gateway_id: r.nat_gateway_id,
      }
    end
  end

  def main_route_table(client)
    client.describe_route_tables(
      filters: [
        { name: "vpc-id", values: [@vpc_id] },
        { name: "association.main", values: ["true"] },
      ],
    ).route_tables.first
  end
end
