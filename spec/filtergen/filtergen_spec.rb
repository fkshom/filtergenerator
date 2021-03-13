require "spec_helper"
require 'filtergen/filtergen'
require 'pathname'

describe Filtergen do
  it "has a version number" do
    expect(Filtergen::VERSION).not_to be nil
  end
end

describe Rule do
  it "add src" do
    rule = Rule.new(src: "192.168.0.1/32")
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

describe Filtergen::Routers::Router1 do
  it "シングルルールからfilterを生成できる" do
    repository = Filtergen::Repository.new()
    repository.add_rule(
      name: 'TERM1',
      src: '192.168.0.0/24',
      srcport: '32768-65535',
      dst: '10.0.1.50/32',
      dstport: '53',
      protocol: 'udp',
      action: 'accept'
    )
    router = Filtergen::Routers::Router1.new()
    router.assign_interface(interfacename: 'irb100', filtername: 'irb100in', direction: 'in', address: '192.168.0.1/24')
    router.set_repository(repository)
    actual = router.create_filter_configuration_data()
    expect(actual).to eq({
      "irb100in" => {
        "TERM1" => {
          src: ['192.168.0.0/24'],
          srcport: ['32768-65535'],
          dst: ['10.0.1.50/32'],
          dstport: ['53'],
          protocol: ['udp'],
          action: 'accept',
        }
      }
    })
  end

  it "マルチルールからfilterを生成できる" do
    repository = Filtergen::Repository.new()
    repository.add_rule(
      name: 'TERM1',
      src: ['192.168.0.0/24', '192.168.0.1/32'],
      srcport: '32768-65535',
      dst: ['10.0.1.50/32', '10.0.1.51/32'],
      dstport: '53',
      protocol: 'udp',
      action: 'accept'
    )
    router = Filtergen::Routers::Router1.new()
    router.assign_interface(interfacename: 'irb100', filtername: 'irb100in', direction: 'in', address: '192.168.0.1/24')
    router.set_repository(repository)
    actual = router.create_filter_configuration_data()
    expect(actual).to eq({
      "irb100in" => {
        "TERM1" => {
          src: ['192.168.0.0/24', '192.168.0.1/32'],
          srcport: ['32768-65535'],
          dst: ['10.0.1.50/32', '10.0.1.51/32'],
          dstport: ['53'],
          protocol: ['udp'],
          action: 'accept',
        }
      }
    })
  end

  it "複数のインタフェースを持つルーターについて、該当インタフェースごとのfilterを生成できる" do
    repository = Filtergen::Repository.new()
    repository.add_rule(
      name: 'TERM1',
      src: ['192.168.0.0/24', '192.168.1.0/24'],
      srcport: '32768-65535',
      dst: ['10.0.1.50/32', '10.0.1.51/32'],
      dstport: '53',
      protocol: 'udp',
      action: 'accept'
    )
    router = Filtergen::Routers::Router1.new()
    router.assign_interface(interfacename: 'irb100', filtername: 'irb100in', direction: 'in', address: '192.168.0.1/24')
    router.assign_interface(interfacename: 'irb110', filtername: 'irb110in', direction: 'in', address: '192.168.1.1/24')
    router.set_repository(repository)
    actual = router.create_filter_configuration_data()
    expect(actual).to eq({
      "irb100in" => {
        "TERM1" => {
          src: ['192.168.0.0/24'],
          srcport: ['32768-65535'],
          dst: ['10.0.1.50/32', '10.0.1.51/32'],
          dstport: ['53'],
          protocol: ['udp'],
          action: 'accept',
        }
      },
      "irb110in" => {
        "TERM1" => {
          src: ['192.168.1.0/24'],
          srcport: ['32768-65535'],
          dst: ['10.0.1.50/32', '10.0.1.51/32'],
          dstport: ['53'],
          protocol: ['udp'],
          action: 'accept',
        }
      }
    })
  end

  it "オブジェクト名を使用したシングルルールからfilterを生成できる" do
    repository = Filtergen::Repository.new()
    repository.add_host(hostname: 'network0', address: '192.168.0.0/24')
    repository.add_host(hostname: 'network1', address: '192.168.1.0/24')
    repository.add_host(hostname: 'host0', address: '10.0.1.50/32')
    repository.add_host(hostname: 'host1', address: '10.0.1.51/32')
    repository.add_port(portname: 'udp53', protocol: 'udp', port: 53)
    repository.add_port(portname: 'default_highport1', port: '32768-65535')
    repository.add_rule(
      name: 'TERM1',
      src: 'network0',
      srcport: '32768-65535',
      dst: 'host0',
      dstport: 'udp53',
      action: 'accept'
    )
    router = Filtergen::Routers::Router1.new()
    router.assign_interface(interfacename: 'irb100', filtername: 'irb100in', direction: 'in', address: '192.168.0.1/24')
    router.set_repository(repository)
    actual = router.create_filter_configuration_data()
    expect(actual).to eq({
      "irb100in" => {
        "TERM1" => {
          src: ['network0'],
          srcport: ['32768-65535'],
          dst: ['host0'],
          dstport: ['udp53'],
          protocol: [nil],
          action: 'accept',
        }
      }
    })
  end

  it "複数のインタフェースを持つルーターについて、該当インタフェースごとのfilterをオブジェクト名を使用したルールから生成できる" do
    repository = Filtergen::Repository.new()
    repository.add_host(hostname: 'network0', address: '192.168.0.0/24')
    repository.add_host(hostname: 'network1', address: '192.168.1.0/24')
    repository.add_host(hostname: 'host0', address: '10.0.1.50/32')
    repository.add_host(hostname: 'host1', address: '10.0.1.51/32')
    repository.add_port(portname: 'udp53', protocol: 'udp', port: 53)
    repository.add_port(portname: 'default_highport1', port: '32768-65535')
    repository.add_rule(
      name: 'TERM1',
      src: ['network0', 'network1'],
      srcport: '32768-65535',
      dst: ['host0', 'host1'],
      dstport: '53',
      protocol: 'udp',
      action: 'accept'
    )
    router = Filtergen::Routers::Router1.new()
    router.assign_interface(interfacename: 'irb100', filtername: 'irb100in', direction: 'in', address: '192.168.0.1/24')
    router.assign_interface(interfacename: 'irb110', filtername: 'irb110in', direction: 'in', address: '192.168.1.1/24')
    router.set_repository(repository)

    actual = router.create_filter_configuration_data()
    expect(actual).to eq({
      "irb100in" => {
        "TERM1" => {
          src: ['network0'],
          srcport: ['32768-65535'],
          dst: ['host0', 'host1'],
          dstport: ['53'],
          protocol: ['udp'],
          action: 'accept',
        }
      },
      "irb110in" => {
        "TERM1" => {
          src: ['network1'],
          srcport: ['32768-65535'],
          dst: ['host0', 'host1'],
          dstport: ['53'],
          protocol: ['udp'],
          action: 'accept',
        }
      }
    })
  end

  it "ルールを文字列に変換できる" do
    repository = Filtergen::Repository.new()
    repository.add_host(hostname: 'network0', address: '192.168.0.0/24')
    repository.add_host(hostname: 'network1', address: '192.168.1.0/24')
    repository.add_host(hostname: 'host0', address: '10.0.1.50/32')
    repository.add_host(hostname: 'host1', address: '10.0.1.51/32')
    repository.add_port(portname: 'udp53', protocol: 'udp', port: 53)
    repository.add_port(portname: 'default_highport1', port: '32768-65535')
    data = {
      "irb100in"=>
      {"TERM1"=>
        {:src=>["network0"],
         :dst=>["host0", "host1"],
         :srcport=>["32768-65535"],
         :dstport=>"53",
         :protocol=>"udp",
         :action=>"accept"}},
     "irb110in"=>
      {"TERM1"=>
        {:src=>["network1"],
         :dst=>["host0", "host1"],
         :srcport=>["32768-65535"],
         :dstport=>"udp53",
         :action=>"accept"}}
    }

    router = Filtergen::Routers::Router1.new()
    router.set_repository(repository)
    actual = router.convert_from_data_to_filter_string(data)
    expect(actual).to eq([
      "set firewall filter irb100in term TERM1 source-address 192.168.0.0/24",
      "set firewall filter irb100in term TERM1 destination-address 10.0.1.50/32",
      "set firewall filter irb100in term TERM1 destination-address 10.0.1.51/32",
      "set firewall filter irb100in term TERM1 source-port 32768-65535",
      "set firewall filter irb100in term TERM1 destination-port 53",
      "set firewall filter irb100in term TERM1 protocol udp",
      "set firewall filter irb100in term TERM1 accept",
      "set firewall filter irb110in term TERM1 source-address 192.168.1.0/24",
      "set firewall filter irb110in term TERM1 destination-address 10.0.1.50/32",
      "set firewall filter irb110in term TERM1 destination-address 10.0.1.51/32",
      "set firewall filter irb110in term TERM1 source-port 32768-65535",
      "set firewall filter irb110in term TERM1 destination-port 53",
      "set firewall filter irb110in term TERM1 protocol udp",
      "set firewall filter irb110in term TERM1 accept",
    ])
  end
end

describe Filtergen::Routers::VDSTF1 do
  it "複数のインタフェースを持つルーターについて、該当インタフェースごとのfilterをオブジェクト名を使用したルールから生成できる" do
    repository = Filtergen::Repository.new()
    repository.add_host(hostname: 'network0', address: '192.168.0.0/24')
    repository.add_host(hostname: 'network1', address: '192.168.1.0/24')
    repository.add_host(hostname: 'host0', address: '10.0.1.50/32')
    repository.add_host(hostname: 'host1', address: '10.0.1.51/32')
    repository.add_port(portname: 'udp53', protocol: 'udp', port: 53)
    repository.add_port(portname: 'default_highport1', port: '32768-65535')
    repository.add_rule(
      name: 'TERM1',
      src: ['network0', 'network1'],
      srcport: '32768-65535',
      dst: ['host0', 'host1'],
      dstport: '53',
      protocol: 'udp',
      action: 'accept'
    )
    vdstf = Filtergen::Routers::VDSTF1.new()
    vdstf.assign_portgroup(dcname: 'vmdc01', portgroupname: 'pg00', address: '192.168.0.1/24')
    vdstf.assign_portgroup(dcname: 'vmdc01', portgroupname: 'pg01', address: '192.168.1.1/24')
    vdstf.set_repository(repository)

    actual = vdstf.create_filter_configuration_data()
    expect(actual).to eq({
      "vmdc01" => {
        "pg00" => [
          { desc: "TERM1", 
            src: ["network0"], dst: ['host0', 'host1'],
            srcport: ['32768-65535'], dstport: ['53'],
            protocol: ['udp'], action: 'accept'
          }
        ],
        "pg01" => [
          { desc: "TERM1", 
            src: ["network1"], dst: ['host0', 'host1'],
            srcport: ['32768-65535'], dstport: ['53'],
            protocol: ['udp'], action: 'accept'
          },
        ]
      }
    })
  end

  it "ルールをobjectに変換できる" do
    repository = Filtergen::Repository.new()
    repository.add_host(hostname: 'network0', address: '192.168.0.0/24')
    repository.add_host(hostname: 'network1', address: '192.168.1.0/24')
    repository.add_host(hostname: 'host0', address: '10.0.1.50/32')
    repository.add_host(hostname: 'host1', address: '10.0.1.51/32')
    repository.add_port(portname: 'udp53', protocol: 'udp', port: 53)
    repository.add_port(portname: 'default_highport1', port: '32768-65535')
    data = {
      "vmdc01" => {
        "pg00" => [
          { desc: "TERM1", 
            src: ["network0"], dst: ['host0', 'host1'],
            srcport: ['32768-65535'], dstport: '53',
            protocol: 'udp', action: 'accept'
          }
        ],
        "pg01" => [
          { desc: "TERM1", 
            src: ["network1"], dst: ['host0', 'host1'],
            srcport: ['32768-65535'], dstport: '53',
            protocol: 'udp', action: 'accept'
          },
        ]
      }
    }

    vdstf = Filtergen::Routers::VDSTF1.new()
    vdstf.set_repository(repository)
    actual = vdstf.convert_from_data_to_filter_string(data)
    expect(actual).to eq({
      "vmdc01" => {
        "pg00" => [
          { desc: "TERM1", 
            src: "192.168.0.0/24", dst: '10.0.1.50/32',
            srcport: '32768-65535', dstport: '53',
            protocol: 'udp', action: 'accept'
          },
          { desc: "TERM1", 
            src: "192.168.0.0/24", dst: '10.0.1.51/32',
            srcport: '32768-65535', dstport: '53',
            protocol: 'udp', action: 'accept'
          }
        ],
        "pg01" => [
          { desc: "TERM1", 
            src: "192.168.1.0/24", dst: '10.0.1.50/32',
            srcport: '32768-65535', dstport: '53',
            protocol: 'udp', action: 'accept'
          },
          { desc: "TERM1", 
            src: "192.168.1.0/24", dst: '10.0.1.51/32',
            srcport: '32768-65535', dstport: '53',
            protocol: 'udp', action: 'accept'
          }
        ],
      }
    })
  end

  it "複数のルールをまとめる" do
    repository = Filtergen::Repository.new()
    repository.add_rule(
      name: 'TERM1',
      src: '192.168.0.2/32',
      srcport: '32768-65535',
      dst: '10.0.1.50/32',
      dstport: '53',
      protocol: 'udp',
      action: 'accept'
    )
    repository.add_rule(
      name: 'TERM1',
      src: '192.168.0.3/32',
      srcport: '32768-65535',
      dst: '10.0.1.51/32',
      dstport: '53',
      protocol: 'udp',
      action: 'accept'
    )
    repository.add_rule(
      name: 'TERM1',
      src: '192.168.0.3/32',
      srcport: '32768-65535',
      dst: '10.0.1.51/32',
      dstport: '53',
      protocol: 'tcp',
      action: 'accept'
    )
    router = Filtergen::Routers::Router1.new()
    router.assign_interface(interfacename: 'irb100', filtername: 'irb100in', direction: 'in', address: '192.168.0.1/24')
    router.set_repository(repository)

    actual = router.aggregate_rules(by: [:dstport, :protocol])
    expect(actual).to eq([
      { name: 'TERM1',
        src: ['192.168.0.2/32', '192.168.0.3/32'],
        srcport: ['32768-65535'],
        dst: ['10.0.1.50/32', '10.0.1.51/32'],
        dstport: ['53'],
        protocol: ['udp'],
        action: 'accept',
      },
      { name: 'TERM1',
        src: ['192.168.0.3/32'],
        srcport: ['32768-65535'],
        dst: ['10.0.1.51/32'],
        dstport: ['53'],
        protocol: ['tcp'],
        action: 'accept',
      },
    ])

    actual = router.aggregate_rules(by: [:src])
    expect(actual).to eq([
      { name: 'TERM1',
        src: ['192.168.0.2/32'],
        srcport: ['32768-65535'],
        dst: ['10.0.1.50/32'],
        dstport: ['53'],
        protocol: ['udp'],
        action: 'accept',
      },
      { name: 'TERM1',
        src: ['192.168.0.3/32'],
        srcport: ['32768-65535'],
        dst: ['10.0.1.51/32'],
        dstport: ['53'],
        protocol: ['tcp', 'udp'],
        action: 'accept',
      },
    ])
  end
end


xdescribe Filtergen::Routers::Router1 do
  it "シングルルールから/24で集約したfilterを生成できる" do
    router = Filtergen::Routers::Router1.new()
    router.assign_interface(interfacename: 'irb100', filtername: 'irb100in', direction: 'in', address: '192.168.0.1/24')
    router.add_rule(
      name: 'TERM1',
      src: '192.168.0.2/32',
      srcport: '32768-65535',
      dst: '10.0.1.50/32',
      dstport: '53',
      protocol: 'udp',
      action: 'accept'
    )
    router.add_rule(
      name: 'TERM1',
      src: '192.168.0.3/32',
      srcport: '32768-65535',
      dst: '10.0.1.51/32',
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
          dst: ['10.0.1.0/24'],
          dstport: '53',
          protocol: 'udp',
          action: 'accept',
        }
      }
    })
  end
end

describe "e2e test" do
  it "a" do
    repository = Filtergen::Repository.new()
    repository.add_host(hostname: 'network0', address: '192.168.0.0/24')
    repository.add_host(hostname: 'network1', address: '192.168.1.0/24')
    repository.add_host(hostname: 'host0', address: '10.0.1.50/32')
    repository.add_host(hostname: 'host1', address: '10.0.1.51/32')
    repository.add_port(portname: 'udp53', protocol: 'udp', port: 53)
    repository.add_port(portname: 'default_highport1', port: '32768-65535')
    repository.add_rule(
      name: 'TERM1',
      src: ['network0', 'network1'],
      srcport: '32768-65535',
      dst: ['host0', 'host1'],
      dstport: '53',
      protocol: 'udp',
      action: 'accept'
    )
    
  end
end
