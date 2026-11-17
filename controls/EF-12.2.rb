# encoding: UTF-8

control "EF-12.2" do
  title "Reverse-proxy / ingress container inventory (informational)"
  desc "Enumerates reverse-proxy / web-proxy containers (nginx, envoy, haproxy, "\
       "traefik, apache) across in-scope Fargate task definitions, so the "\
       "ingress topology is visible and each proxy's in-container TLS "\
       "configuration can be validated with cis-nginx. Informational — no "\
       "pass/fail (impact 0.0)."
  tag severity:              "none"
  tag severity_source:       "assessed"
  tag nist:                  ['CM-8 a 1']
  tag ksi:                   ['KSI-PIY-GIV']
  tag nist_r4:               ['CM-8']
  tag cci:                   ['CCI-003962']
  tag local_number:          "EF-12.2"
  tag srg:                   "SRG-APP-000439-CTR-001070"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  impact 0.0
  proxies = proxy_containers

  if proxies.empty?
    describe "Reverse-proxy containers detected in scope" do
      subject { proxies }
      it { should be_empty }
    end
  else
    proxies.each do |p|
      describe "Proxy container #{p[:family]}/#{p[:name]} — image (validate TLS config via cis-nginx)" do
        subject { p[:image] }
        it { should_not be_nil }
      end
    end
  end
end
