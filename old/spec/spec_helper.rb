require "bundler/setup"
require "super_diff/rspec"
require "filtergen"

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = ".rspec_status"
  config.filter_run_when_matching :focus
  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end
