# encoding: UTF-8

control "EF-12.1" do
  title "Reverse-proxy TLS termination must be wired where declared"
  desc "When this workload terminates TLS at a reverse proxy rather than (or in "\
       "addition to) the ALB — `tls_termination` is 'proxy' or 'both' — a "\
       "reverse-proxy container (nginx/envoy/haproxy/traefik/apache) must be "\
       "present in the Fargate task definitions and have TLS key material wired "\
       "(a secret, env var, or mounted volume referencing a certificate/key). "\
       "Fail-closed: proxy termination is declared but no proxy holds TLS "\
       "material means TLS is not actually terminating where claimed. The "\
       "proxy's cipher/protocol configuration is validated inside the container "\
       "by cis-nginx (nginx_tls_termination). SC-8 / SC-8(1) / SC-13."
  desc  'check', "
    Applies when the input `tls_termination` is `proxy` or `both`. At least one container in the in-scope Fargate task definitions must be a reverse proxy, identified by an image or container name matching nginx, envoy, haproxy, traefik, httpd, apache or proxy. Each proxy found must have TLS material wired in: a secret, environment variable or mount point whose name or path mentions tls, ssl, cert, key, pem, crt or pkcs.
  "
  desc  'fix', "
    Deliver the proxy's certificate and private key from Secrets Manager through the container's `secrets` block, or from a mounted volume, and configure the proxy to terminate TLS with them. Register a new task definition revision with the change (`aws ecs register-task-definition --cli-input-json file://taskdef.json`), then update the service to use it (`aws ecs update-service --cluster <cluster> --service <service> --task-definition <family>:<revision>`).

    If TLS actually terminates at the load balancer, set `tls_termination` to `alb`. Validate the proxy's own TLS configuration with the cis-nginx profile.
  "
  tag severity:              "high"
  tag severity_source:       "assessed"
  tag nist:                  ['SC-8', 'SC-8 (1)']
  tag ksi:                   ['KSI-CNA-MAT', 'KSI-CNA-ULN', 'KSI-SVC-SIN']
  tag nist_r4:               ['SC-8', 'SC-8 (1)']
  tag cci:                   ['CCI-002418', 'CCI-002421']
  tag local_number:          "EF-12.1"
  tag srg:                   "SRG-APP-000439-CTR-001070"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  mode       = input("tls_termination", value: "alb").to_s.downcase
  applicable = %w(proxy both).include?(mode)
  proxies    = applicable ? proxy_containers : []

  impact 0.7
  impact 0.0 unless applicable
  only_if("tls_termination=#{mode}: TLS terminates at the ALB (validated by EF-11), not a proxy") { applicable }

  describe "Reverse-proxy container present for proxy TLS termination (tls_termination=#{mode})" do
    subject { proxies.map { |p| "#{p[:family]}/#{p[:name]}" } }
    it { should_not be_empty }
  end

  proxies.each do |p|
    has_tls = container_has_tls_material?(p[:def])
    describe "Proxy #{p[:family]}/#{p[:name]} (#{p[:image]}) has TLS key material wired" do
      subject { has_tls }
      it { should eq true }
    end
  end
end
