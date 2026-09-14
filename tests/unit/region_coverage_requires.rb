# frozen_string_literal: true
#
# SDK gems for every service this repository's region_coverage_manifest.yml
# watches. Literal top-of-file requires, in a file of their own, because
# Aws.config[:<service>] raises until the gem that registers that key is loaded.
# region_coverage_test.rb reconciles this list against the manifest and fails
# with the exact line to add if they drift.

require "aws-sdk-ec2"
require "aws-sdk-ecs"
require "aws-sdk-elasticloadbalancingv2"
