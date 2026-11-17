# encoding: UTF-8

control "EF-8.5" do
  title "Services should enable the deployment circuit breaker"
  desc "The deployment circuit breaker auto-rolls-back failed deployments, "\
       "supporting availability."
  desc  'check', "
    For every Fargate ECS service in the scan regions, `deploymentConfiguration.deploymentCircuitBreaker.enable` must be true.
  "
  desc  'fix', "
    ```
    aws ecs update-service --cluster <cluster> --service <service> --deployment-configuration 'deploymentCircuitBreaker={enable=true,rollback=true}'
    ```
  "
  tag severity:              "low"
  tag severity_source:       "assessed"
  tag nist:                  ['CP-10']
  tag ksi:                   ['KSI-RPL-ABO', 'KSI-RPL-ARP', 'KSI-RPL-RRO', 'KSI-RPL-TRC']
  tag nist_r4:               ['CP-10']
  tag cci:                   ['CCI-004028']
  tag local_number:          "EF-8.5"
  tag applicable_partitions: ["aws", "aws-us-gov"]
  tag implementation_status: "implemented"

  keys = ecs_service_keys
  impact 0.3
  impact 0.0 if keys.empty?
  only_if("No ECS services in scope") { !keys.empty? }

  keys.each do |k|
    svc = aws_ecs_service_full(cluster: k[:cluster], service: k[:service])
    next unless svc.fargate?

    describe "Deployment circuit breaker for service #{svc.service_name}" do
      subject { svc.circuit_breaker_enabled? }
      it { should eq true }
    end
  end
end
