require "spec_helper"
require 'pathname'

describe Filtergen::Repository::Rule do
  it "add src" do
    rule = Filtergen::Repository::Rule.new(src: "192.168.0.1/32")
    rule.src = rule.src + ["192.168.0.1/32"]
    rule.src = rule.src + ["192.168.0.2/32"]
    expect(rule.src).to eq(['192.168.0.1/32', '192.168.0.2/32'])
  end
  it "to_h" do
    rule = Filtergen::Repository::Rule.new(src: "192.168.0.1/32")
    expect(rule.to_h).to eq({
      name: nil,
      src: ['192.168.0.1/32'],
      dst: [],
      srcport: [],
      dstport: [],
      protocol: [],
      action: nil,
    })
  end
end

describe Filtergen::Repository::Rules do
  xit "each" do
    rules = Filtergen::Repository::Rules.new()
    rules << Filtergen::Repository::Rule.new(
      name: 'TERM1',
      src: ['192.168.0.0/24', '192.168.1.0/24'],
      srcport: '32768-65535',
      dst: '10.0.1.50/32',
      dstport: '53',
      protocol: 'udp',
      action: 'accept',
    )
    actual = rules.flatten_grep(target: :src){|partial_rule|
      partial_rule[:src] != '192.168.0.0/24'
    }.map(&:to_h)
    expect(actual).to eq([
      {
        name: 'TERM1',
        src: ['192.168.1.0/24'],
        srcport: ['32768-65535'],
        dst: ['10.0.1.50/32'],
        dstport: ['53'],
        protocol: ['udp'],
        action: 'accept',
      }
    ])
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