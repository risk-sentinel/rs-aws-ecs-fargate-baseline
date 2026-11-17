# encoding: UTF-8
#
# aws_guardduty_ecs_coverage — GuardDuty Runtime Monitoring coverage for ECS/
# Fargate, region by region. GuardDuty is NOT in inspec-aws's AwsConnection
# closed list, so clients are constructed directly per region.
#
#   describe aws_guardduty_ecs_coverage(regions: ['us-east-1']) do
#     its('unreadable_regions') { should be_empty }
#     its('uncovered_regions')  { should be_empty }
#   end
#
# A region is covered when it has an ENABLED detector whose RUNTIME_MONITORING
# feature is ENABLED with its ECS_FARGATE_AGENT_MANAGEMENT additional
# configuration ENABLED. Without agent management, Fargate tasks get no
# GuardDuty agent, so runtime monitoring "on" alone does not cover them.
#
# GuardDuty is regional: a detector in one region says nothing about another.
# A region that cannot be read is reported in unreadable_regions, never as
# covered or uncovered.

class AwsGuarddutyEcsCoverage < AwsResourceBase
  name "aws_guardduty_ecs_coverage"
  desc "GuardDuty Runtime Monitoring + Fargate agent management, per region."
  example "
    describe aws_guardduty_ecs_coverage(regions: ['us-east-1']) do
      its('uncovered_regions') { should be_empty }
    end
  "

  attr_reader :regions

  def initialize(opts = {})
    super(opts)
    validate_parameters(allow: %i[regions])
    @regions = Array(opts[:regions]).map(&:to_s).reject(&:empty?).uniq
    @gaps = {}
    @unreadable = {}
    @regions.each { |r| assess(r) }
  end

  # region => why it is not covered.
  def uncovered_regions
    @gaps.map { |r, why| "#{r}: #{why}" }
  end

  # region => the error that stopped it being read.
  def unreadable_regions
    @unreadable.map { |r, err| "#{r}: #{err}" }
  end

  def to_s
    "GuardDuty ECS/Fargate runtime coverage (#{@regions.join(', ')})"
  end

  private

  def assess(region)
    gd = ::Aws::GuardDuty::Client.new(region: region)
    detectors = Array(gd.list_detectors.detector_ids).map { |id| gd.get_detector(detector_id: id) }
    enabled = detectors.select { |d| d.status.to_s.casecmp("ENABLED").zero? }
    return @gaps[region] = "no enabled detector" if enabled.empty?

    runtime = enabled.map { |d| feature(d, "RUNTIME_MONITORING") }.compact
                     .select { |f| on?(f.status) }
    return @gaps[region] = "RUNTIME_MONITORING not enabled" if runtime.empty?

    agent = runtime.any? do |f|
      Array(f.additional_configuration).any? { |c| c.name.to_s.casecmp("ECS_FARGATE_AGENT_MANAGEMENT").zero? && on?(c.status) }
    end
    @gaps[region] = "ECS_FARGATE_AGENT_MANAGEMENT not enabled" unless agent
  rescue StandardError => e
    @unreadable[region] = e.class.name
  end

  def feature(detector, name)
    Array(detector.features).find { |f| f.name.to_s.casecmp(name).zero? }
  end

  def on?(status)
    status.to_s.casecmp("ENABLED").zero?
  end
end
