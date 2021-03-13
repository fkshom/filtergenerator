require "spec_helper"
require 'pathname'

describe Filtergen::Repository::Rule do
  it "add src" do
    rule = Filtergen::Repository::Rule.new(src: "192.168.0.1/32")
    rule.src = rule.src + ["192.168.0.1/32"]
    rule.src = rule.src + ["192.168.0.2/32"]
    expect(rule.src).to eq(['192.168.0.1/32', '192.168.0.2/32'])
  end
end

describe Filtergen::Repository do
  it "add rule" do
    repository = Filtergen::Repository.new()
    repository.add_rule(
      name: 'TERM1',
      src: '192.168.0.0/24',
      srcport: '32768-65535',
      dst: '10.0.1.50/32',
      dstport: '53',
      protocol: 'udp',
      action: 'accept',
      only: ['router1'],
      tags: [:specific_router1]
    )
  end
end