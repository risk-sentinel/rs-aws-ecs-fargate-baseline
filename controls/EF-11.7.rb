# encoding: UTF-8

control "EF-11.7" do
  title "ALB HTTPS listener certificates must be valid (issued, not expiring)"
  desc "The ACM certificate bound to each HTTPS/TLS listener must be in ISSUED "\
       "status and more than `cert_expiry_warning_days` from expiry, so clients "\
       "are never served an expired or about-to-expire certificate ("\
       "SC-17 / SC-8(1)). A strong SSL policy (EF-11.2) on an expired cert still "\
       "breaks TLS — this control closes that gap."
  tag severity:              "high"
  tag severity_source:       "assessed"
  tag nist:                  ['SC-17 a', 'SC-8 (1)']
  tag ksi:                   ['KSI-SVC-ASM', 'KSI-SVC-SIN']
  tag nist_r4:               ['SC-17', 'SC-8 (1)']
  tag cci:                   ['CCI-001159', 'CCI-002421']
  tag local_number:          "EF-11.7"
  tag srg:                   "SRG-APP-000516-CTR-001335"
  tag fsbp:                  "ACM.1"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  albs  = elbv2_internet_facing
  grace = input("cert_expiry_warning_days", value: 30)
  impact 0.7
  impact 0.0 if albs.empty?
  only_if("No internet-facing Application Load Balancers in scope") { !albs.empty? }

  cert_arns = albs.flat_map do |lb|
    lst = aws_elasticloadbalancingv2_listeners(load_balancer_arn: lb[:arn])
    lst.protocols.zip(lst.certificates).flat_map do |proto, certs|
      next [] unless %w(HTTPS TLS).include?(proto.to_s)
      Array(certs).map { |c| c.respond_to?(:certificate_arn) ? c.certificate_arn : c[:certificate_arn] }
    end
  end.compact.reject { |a| a.to_s.empty? }.uniq

  if cert_arns.empty?
    describe "ALB HTTPS-listener certificates" do
      skip "No HTTPS/TLS listener certificate ARNs resolved on in-scope internet-facing ALBs."
    end
  end

  cert_arns.each do |arn|
    cert = aws_acm_certificate(certificate_arn: arn)
    unless cert.available?
      describe "ACM certificate #{arn.to_s.split('/').last}" do
        skip "aws-sdk-acm not present in the scanner image — cannot read certificate "\
             "status/expiry. Add aws-sdk-acm via risk-sentinel/container-build-sign."
      end
      next
    end

    days = cert.days_until_expiry
    describe "ACM certificate #{arn.to_s.split('/').last} (#{cert.domain_name})" do
      it "is in ISSUED status" do
        expect(cert.issued?).to eq(true)
      end
      it "is more than #{grace} days from expiry (#{days.inspect} days remaining)" do
        expect(days).not_to be_nil
        expect(days.to_i).to be > grace.to_i
      end
    end
  end
end
