# encoding: UTF-8
#
# aws_ecs_account_settings — effective ECS account-level settings
# (ecs:ListAccountSettings, effective_settings: true). Lets EF-10.2 assert
# account-wide defaults the per-cluster controls can't see, e.g.
# containerInsights default-on, awsvpcTrunking, tag-resource propagation.
#
#   describe aws_ecs_account_settings do
#     its('value_for("containerInsights")') { should cmp 'enabled' }
#   end
#
# "Account-level" is a misnomer in the API: ECS account settings are stored and
# applied PER REGION. The same setting can be enabled in one region and
# disabled in another, so this resource sweeps the supplied region scope rather
# than reading whichever region the client happened to default to.
#
# A single-region read made every EF-10.2 assertion a statement about one
# region while reading as a statement about the account.
#
# DIVERGENCE IS SURFACED, NOT AVERAGED. value_for returns the value only when
# every scanned region agrees. When they disagree it returns a description of
# the disagreement, which cannot cmp-match an expected value — so the control
# fails and says why, instead of passing on the first region that happens to be
# compliant. values_for exposes the per-region detail for evidence.
#
# On an AWS API error for a region, each_region_client records the reason in
# region_errors and continues; region_error_summary surfaces it as a
# connection_error, so an unreadable region stays visible as unassessed rather
# than counting as agreement.

class AwsEcsAccountSettings < AwsResourceBase
  include RegionScope
  name "aws_ecs_account_settings"
  desc "Effective ECS account-level settings (ListAccountSettings), per region."
  example "
    describe aws_ecs_account_settings do
      its('value_for(\"containerInsights\")') { should cmp 'enabled' }
      its('divergent_settings') { should be_empty }
    end
  "

  attr_reader :settings_by_region

  def initialize(opts = {})
    opts = opts.dup
    # Removed BEFORE super: AwsResourceBase forwards unknown keys to
    # validate_parameters, which raises on anything outside its allow-list.
    region_override = Array(opts.delete(:regions))
    super(opts)
    validate_parameters
    @all_regions = region_scope_or_fail!(@aws, region_override)
    @settings_by_region = fetch_settings
  end

  def fetch_settings
    out = {}
    each_region_client(::Aws::ECS::Client) do |client, region|
      found = {}
      token = nil
      loop do
        args = { effective_settings: true }
        args[:next_token] = token if token
        resp = client.list_account_settings(args)
        break unless resp
        Array(resp.settings).each { |s| found[s.name.to_s] = s.value }
        token = resp.next_token
        break if token.nil? || token.to_s.empty?
      end
      out[region] = found
    end
    out
  end

  # Every setting name seen in any scanned region.
  def setting_names
    @settings_by_region.values.flat_map(&:keys).uniq.sort
  end

  # region => value, for one setting. The evidence behind value_for.
  def values_for(name)
    @settings_by_region.each_with_object({}) do |(region, found), acc|
      acc[region] = found[name.to_s]
    end
  end

  # Names whose value is not identical across every scanned region. A setting in
  # here is a real finding: the account is not uniformly configured.
  def divergent_settings
    setting_names.select { |n| values_for(n).values.uniq.length > 1 }
  end

  # Effective value when the scanned regions agree.
  #
  # When they do not, this returns a description of the disagreement rather than
  # picking one. `should cmp 'enabled'` then fails and prints which region holds
  # which value — the alternative is returning 'enabled' because one region was
  # compliant, which is the defect this resource was rewritten to remove.
  def value_for(name)
    seen = values_for(name)
    values = seen.values.uniq
    return values.first if values.length <= 1

    "divergent across regions: " +
      seen.sort.map { |region, value| "#{region}=#{value.inspect}" }.join(", ")
  end

  def to_s
    "ECS Account Settings (#{regions_scanned.length} region(s))"
  end
end
