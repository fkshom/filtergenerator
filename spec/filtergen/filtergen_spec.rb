require "spec_helper"
require 'filtergen/filtergen'
require 'pathname'

describe Filtergen do
  it "has a version number" do
    expect(Filtergen::VERSION).not_to be nil
  end
end

describe Filtergen::Repository do
  let(:unko) do
    []
  end
end

describe Filtergen::Routers::Router1 do
  it "シングルルールからfilterを生成できる" do
    router = Filtergen::Routers::Router1.new()
    router.assign_interface(interfacename: 'irb100', filtername: 'irb100in', direction: 'in', address: '192.168.0.1/24')
    router.add_rule(
      name: 'TERM1',
      src: '192.168.0.0/24',
      srcport: '32768-65535',
      dst: '10.0.1.50/32',
      dstport: '53',
      protocol: 'udp',
      action: 'accept'
    )
    actual = router.create_filter_configuration_data()
    expect(actual).to eq({
      "irb100in" => {
        "TERM1" => {
          src: ['192.168.0.0/24'],
          srcport: ['32768-65535'],
          dst: ['10.0.1.50/32'],
          dstport: '53',
          protocol: 'udp',
          action: 'accept',
        }
      }
    })
  end

  it "マルチルールからfilterを生成できる" do
    router = Filtergen::Routers::Router1.new()
    router.assign_interface(interfacename: 'irb100', filtername: 'irb100in', direction: 'in', address: '192.168.0.1/24')
    router.add_rule(
      name: 'TERM1',
      src: ['192.168.0.0/24', '192.168.0.1/32'],
      srcport: '32768-65535',
      dst: ['10.0.1.50/32', '10.0.1.51/32'],
      dstport: '53',
      protocol: 'udp',
      action: 'accept'
    )
    actual = router.create_filter_configuration_data()
    expect(actual).to eq({
      "irb100in" => {
        "TERM1" => {
          src: ['192.168.0.0/24', '192.168.0.1/32'],
          srcport: ['32768-65535'],
          dst: ['10.0.1.50/32', '10.0.1.51/32'],
          dstport: '53',
          protocol: 'udp',
          action: 'accept',
        }
      }
    })
  end

  it "複数のインタフェースを持つルーターについて、該当インタフェースごとのfilterを生成できる" do
    router = Filtergen::Routers::Router1.new()
    router.assign_interface(interfacename: 'irb100', filtername: 'irb100in', direction: 'in', address: '192.168.0.1/24')
    router.assign_interface(interfacename: 'irb110', filtername: 'irb110in', direction: 'in', address: '192.168.1.1/24')
    router.add_rule(
      name: 'TERM1',
      src: ['192.168.0.0/24', '192.168.1.0/24'],
      srcport: '32768-65535',
      dst: ['10.0.1.50/32', '10.0.1.51/32'],
      dstport: '53',
      protocol: 'udp',
      action: 'accept'
    )
    actual = router.create_filter_configuration_data()
    expect(actual).to eq({
      "irb100in" => {
        "TERM1" => {
          src: ['192.168.0.0/24'],
          srcport: ['32768-65535'],
          dst: ['10.0.1.50/32', '10.0.1.51/32'],
          dstport: '53',
          protocol: 'udp',
          action: 'accept',
        }
      },
      "irb110in" => {
        "TERM1" => {
          src: ['192.168.1.0/24'],
          srcport: ['32768-65535'],
          dst: ['10.0.1.50/32', '10.0.1.51/32'],
          dstport: '53',
          protocol: 'udp',
          action: 'accept',
        }
      }
    })
  end

  it "オブジェクト名を使用したシングルルールからfilterを生成できる" do
    repository = Filtergen::Repository.new()
    repository.add_host_object(hostname: 'network0', address: '192.168.0.0/24')
    repository.add_host_object(hostname: 'network1', address: '192.168.1.0/24')
    repository.add_host_object(hostname: 'host0', address: '10.0.1.50/32')
    repository.add_host_object(hostname: 'host1', address: '10.0.1.51/32')
    repository.add_port_object(portname: 'udp53', protocol: 'udp', port: 53)
    repository.add_port_object(portname: 'default_highport1', port: '32768-65535')

    router = Filtergen::Routers::Router1.new()
    router.assign_interface(interfacename: 'irb100', filtername: 'irb100in', direction: 'in', address: '192.168.0.1/24')
    router.set_repository(repository)
    router.add_rule(
      name: 'TERM1',
      src: 'network0',
      srcport: '32768-65535',
      dst: 'host0',
      dstport: 'udp53',
      action: 'accept'
    )
    actual = router.create_filter_configuration_data()
    expect(actual).to eq({
      "irb100in" => {
        "TERM1" => {
          src: ['network0'],
          srcport: ['32768-65535'],
          dst: ['host0'],
          dstport: '53',
          protocol: 'udp',
          action: 'accept',
        }
      }
    })
  end

  it "複数のインタフェースを持つルーターについて、該当インタフェースごとのfilterをオブジェクト名を使用したルールから生成できる" do
    repository = Filtergen::Repository.new()
    repository.add_host_object(hostname: 'network0', address: '192.168.0.0/24')
    repository.add_host_object(hostname: 'network1', address: '192.168.1.0/24')
    repository.add_host_object(hostname: 'host0', address: '10.0.1.50/32')
    repository.add_host_object(hostname: 'host1', address: '10.0.1.51/32')
    repository.add_port_object(portname: 'udp53', protocol: 'udp', port: 53)
    repository.add_port_object(portname: 'default_highport1', port: '32768-65535')

    router = Filtergen::Routers::Router1.new()
    router.assign_interface(interfacename: 'irb100', filtername: 'irb100in', direction: 'in', address: '192.168.0.1/24')
    router.assign_interface(interfacename: 'irb110', filtername: 'irb110in', direction: 'in', address: '192.168.1.1/24')
    router.set_repository(repository)
    router.add_rule(
      name: 'TERM1',
      src: ['network0', 'network1'],
      srcport: '32768-65535',
      dst: ['host0', 'host1'],
      dstport: '53',
      protocol: 'udp',
      action: 'accept'
    )
    actual = router.create_filter_configuration_data()
    expect(actual).to eq({
      "irb100in" => {
        "TERM1" => {
          src: ['network0'],
          srcport: ['32768-65535'],
          dst: ['host0', 'host1'],
          dstport: '53',
          protocol: 'udp',
          action: 'accept',
        }
      },
      "irb110in" => {
        "TERM1" => {
          src: ['network1'],
          srcport: ['32768-65535'],
          dst: ['host0', 'host1'],
          dstport: '53',
          protocol: 'udp',
          action: 'accept',
        }
      }
    })
  end
end
