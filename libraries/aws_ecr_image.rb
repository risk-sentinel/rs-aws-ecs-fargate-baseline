# encoding: UTF-8
#
# aws_ecr_image — one ECR image, by digest: scan findings (EF-1.7), signature
# (EF-1.5) and SBOM (EF-1.6).
#
# Queried in the image's own region and registry (both parsed from the image
# URI by the scope helpers), not the scanner's default region and account.
#
# A signature can attach three unrelated ways, and any one counts:
#   1. cosign's tag scheme: `sha256-<digest>.sig` in the same repository;
#   2. an OCI 1.1 referrer whose subject is the image digest;
#   3. AWS-native signing (Signer / Notation), counted only when COMPLETE.
# An SBOM is a cosign `.att`/`.sbom` tag, or a referrer naming SPDX, CycloneDX
# or an attestation envelope.
#
# "Could not determine" is kept apart from "no": an API error never reads as
# unsigned. Controls assert *_determined? before asserting the answer.

class AwsEcrImage < AwsResourceBase
  name "aws_ecr_image"
  desc "ECR image by digest: scan findings, signature and SBOM presence."
  example "
    img = aws_ecr_image(repository_name: 'app', image_digest: 'sha256:...', region: 'us-east-1', registry_id: '123456789012')
    describe img do
      it { should be_signing_determined }
      it { should be_signed }
    end
  "

  SIGNATURE_MEDIA = /cosign\.artifact\.sig|simplesigning|notary\.signature|notation\.signature|sigstore\.bundle/i.freeze
  ATTESTATION_MEDIA = /cosign\.artifact\.att|dsse\.envelope|in-toto/i.freeze
  SBOM_MEDIA = /spdx|cyclonedx|\bsbom\b/i.freeze

  attr_reader :repository_name, :image_digest, :region, :registry_id, :image_scan_findings

  def initialize(opts = {})
    super(opts)
    validate_parameters(required: %i[repository_name image_digest], allow: %i[region registry_id])
    @repository_name = opts[:repository_name]
    @image_digest    = opts[:image_digest]
    @region          = opts[:region].to_s
    @registry_id     = opts[:registry_id].to_s
    @image_scan_findings = nil
    @errors = {}
    catch_aws_errors do
      resp = ecr.describe_image_scan_findings(**target, image_id: { image_digest: @image_digest })
      @image_scan_findings = resp.image_scan_findings&.to_h
    rescue Aws::ECR::Errors::ScanNotFoundException, Aws::ECR::Errors::ImageNotFoundException
      @image_scan_findings = nil
    end
  end

  def signed?
    return @signed unless @signed.nil?
    @signed = cosign_tag?("sig") || referrer_match?(SIGNATURE_MEDIA) || native_signing_complete?
  end

  # False only when no signature was found AND a lookup that could have found
  # one failed: the answer is unknown, not "unsigned".
  def signing_determined?
    return true if signed?
    !(@errors.key?(:tags) || @errors.key?(:referrers) || @errors.key?(:native))
  end

  def has_sbom?
    return @has_sbom unless @has_sbom.nil?
    @has_sbom = cosign_tag?("att") || cosign_tag?("sbom") ||
                referrer_match?(SBOM_MEDIA) || referrer_match?(ATTESTATION_MEDIA)
  end

  def sbom_determined?
    return true if has_sbom?
    !(@errors.key?(:tags) || @errors.key?(:referrers))
  end

  # The lookups that failed, so an unknown result says why.
  def lookup_errors
    @errors.map { |k, v| "#{k}: #{v}" }.join("; ")
  end

  def to_s
    "ECR Image #{@repository_name}@#{@image_digest.to_s[0, 16]}"
  end

  private

  def ecr
    @ecr ||= @region.empty? ? @aws.ecr_client : ::Aws::ECR::Client.new(region: @region)
  end

  def target
    t = { repository_name: @repository_name }
    t[:registry_id] = @registry_id unless @registry_id.empty?
    t
  end

  def cosign_tag?(suffix)
    tag = "sha256-#{@image_digest.to_s.delete_prefix('sha256:')}.#{suffix}"
    ecr.describe_images(**target, image_ids: [{ image_tag: tag }])
    true
  rescue Aws::ECR::Errors::ImageNotFoundException
    false
  rescue StandardError => e
    @errors[:tags] = e.class.name
    false
  end

  def referrers
    @referrers ||= begin
      refs = []
      token = nil
      loop do
        args = { **target, subject_id: { image_digest: @image_digest } }
        args[:next_token] = token if token
        resp = ecr.list_image_referrers(**args)
        refs.concat(Array(resp.referrers))
        token = resp.next_token
        break if token.nil? || token.to_s.empty?
      end
      refs
    end
  end

  def referrer_match?(pattern)
    referrers.any? do |r|
      %i[artifact_media_type artifact_type media_type].any? { |m| r.respond_to?(m) && r.public_send(m).to_s =~ pattern }
    end
  rescue StandardError => e
    @errors[:referrers] = e.class.name
    false
  end

  def native_signing_complete?
    statuses = Array(ecr.describe_image_signing_status(**target, image_id: { image_digest: @image_digest }).signing_statuses)
    statuses.any? { |s| s.status.to_s.casecmp("COMPLETE").zero? }
  rescue StandardError => e
    @errors[:native] = e.class.name
    false
  end
end
